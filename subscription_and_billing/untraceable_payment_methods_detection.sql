-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: UNTRACEABLE PAYMENT METHODS
-- =============================================================================
-- File:     untraceable_payment_methods_detection.sql
-- Signal:   S08 of 10 — Subscription & Recurring Billing Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Gift cards and prepaid methods used specifically to avoid traceability on
-- recurring charges. Legitimate subscribers use credit or debit cards tied
-- to their identity. Fraudulent or abuse-prone accounts disproportionately
-- use prepaid cards, gift cards, virtual card numbers, or privacy-focused
-- payment methods that make chargebacks difficult to contest and account
-- bans easy to circumvent.
--
-- BEHAVIORAL TELL:
-- The payment method type alone isn't sufficient — many legitimate users
-- use prepaid cards. The behavioral signal is prepaid/gift card usage
-- combined with other risk indicators: short account lifespans, no
-- identity verification, multiple accounts from the same device, or
-- transaction patterns that suggest the account is disposable. The
-- combination of untraceable payment + disposable behavior is the tell.
--
-- DATA REQUIREMENTS:
-- Requires: account_id, payment_method_id, payment_method_type,
--           charge_id, charge_amount, charge_date, charge_status
-- Optional: account_created_at, device_id, ip_address, card_bin,
--           card_funding_source, account_verification_status
--
-- TUNING PARAMETERS:
-- * prepaid_types            — payment types considered untraceable (default: 'prepaid','gift_card','virtual')
-- * min_charges              — minimum charges before analysis (default: 2)
-- * short_lifespan_days      — account lifespan below which = disposable (default: 45)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $5K–$50K per untraceable cluster
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_charges AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        payment_method_id       AS payment_method_id,        -- expected: VARCHAR / STRING
        payment_method_type     AS payment_method_type,      -- expected: VARCHAR ('credit','debit','prepaid','gift_card','virtual')
        card_funding_source     AS card_funding_source,      -- expected: VARCHAR ('credit','debit','prepaid',NULL)
        charge_id               AS charge_id,                -- expected: VARCHAR / STRING
        amount                  AS charge_amount,            -- expected: FLOAT / NUMBER
        charge_date             AS charge_date,              -- expected: TIMESTAMP_NTZ
        status                  AS charge_status,            -- expected: VARCHAR ('succeeded','failed','disputed')

    FROM your_charge_table                                   -- << REPLACE WITH YOUR TABLE

),

normalized_accounts AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        created_at              AS account_created_at,        -- expected: TIMESTAMP_NTZ
        device_id               AS device_id,                -- expected: VARCHAR
        ip_address              AS ip_address,               -- expected: VARCHAR
        verification_status     AS account_verification_status, -- expected: VARCHAR ('verified','unverified',NULL)
        cancelled_at            AS account_cancelled_at,     -- expected: TIMESTAMP_NTZ (NULL if active)

    FROM your_account_table                                  -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        45      AS short_lifespan_days,         -- account lasting < 45 days = likely disposable
        2       AS min_charges,                 -- need at least 2 charges to establish pattern
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

charges_in_scope AS (
    SELECT *
    FROM normalized_charges
    WHERE charge_date >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 1: Identify accounts using untraceable payment methods
untraceable_accounts AS (
    SELECT
        c.account_id,
        COUNT(DISTINCT c.charge_id)                         AS total_charges,
        SUM(c.charge_amount)                                AS total_charged,
        COUNT(CASE WHEN c.payment_method_type IN ('prepaid', 'gift_card', 'virtual')
                    OR c.card_funding_source = 'prepaid'
              THEN 1 END)                                   AS untraceable_charges,
        ROUND(100.0 * COUNT(CASE WHEN c.payment_method_type IN ('prepaid', 'gift_card', 'virtual')
                    OR c.card_funding_source = 'prepaid'
              THEN 1 END) / NULLIF(COUNT(*), 0), 1)         AS untraceable_pct,
        COUNT(CASE WHEN c.charge_status = 'disputed' THEN 1 END)
                                                            AS dispute_count,
        COUNT(CASE WHEN c.charge_status = 'failed' THEN 1 END)
                                                            AS failure_count,
        COUNT(DISTINCT c.payment_method_id)                 AS distinct_payment_methods,
        MODE(c.payment_method_type)                         AS primary_payment_type
    FROM charges_in_scope c
    GROUP BY c.account_id
    HAVING COUNT(CASE WHEN c.payment_method_type IN ('prepaid', 'gift_card', 'virtual')
                       OR c.card_funding_source = 'prepaid' THEN 1 END) > 0
),

-- Step 2: Enrich with account metadata
account_risk_profile AS (
    SELECT
        ua.*,
        na.account_created_at,
        na.device_id,
        na.ip_address,
        na.account_verification_status,
        na.account_cancelled_at,
        DATEDIFF('day', na.account_created_at,
                 COALESCE(na.account_cancelled_at, CURRENT_TIMESTAMP()))
                                                            AS account_lifespan_days,
        CASE WHEN na.account_cancelled_at IS NOT NULL THEN TRUE ELSE FALSE END
                                                            AS is_cancelled
    FROM untraceable_accounts ua
    INNER JOIN normalized_accounts na
        ON ua.account_id = na.account_id
),

-- Step 3: Detect device/IP reuse across untraceable accounts
shared_infra AS (
    SELECT
        device_id,
        ip_address,
        COUNT(DISTINCT account_id)                          AS accounts_on_infra
    FROM account_risk_profile
    WHERE device_id IS NOT NULL
    GROUP BY device_id, ip_address
    HAVING COUNT(DISTINCT account_id) >= 2
),

-- Step 4: Score and flag
flagged_accounts AS (
    SELECT
        arp.*,
        COALESCE(si.accounts_on_infra, 1)                   AS accounts_on_shared_infra,
        CASE
            WHEN arp.untraceable_pct = 100
             AND arp.account_lifespan_days <= (SELECT short_lifespan_days FROM thresholds)
             AND COALESCE(si.accounts_on_infra, 1) >= 3      THEN 'HIGH — Disposable + Untraceable + Clustered'
            WHEN arp.untraceable_pct = 100
             AND arp.account_lifespan_days <= (SELECT short_lifespan_days FROM thresholds)
                                                            THEN 'HIGH — Disposable Account + Untraceable Payment'
            WHEN arp.untraceable_pct >= 80
             AND arp.account_verification_status = 'unverified'
             AND arp.dispute_count >= 1                      THEN 'MEDIUM — Unverified + Untraceable + Disputes'
            WHEN COALESCE(si.accounts_on_infra, 1) >= 3
             AND arp.untraceable_pct >= 50                   THEN 'MEDIUM — Multi-Account + Untraceable'
            WHEN arp.untraceable_pct = 100
             AND arp.distinct_payment_methods >= 3           THEN 'MEDIUM — Multiple Untraceable Methods'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM account_risk_profile arp
    LEFT JOIN shared_infra si
        ON arp.device_id = si.device_id
    CROSS JOIN thresholds t
    WHERE arp.total_charges >= t.min_charges
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    account_id,
    total_charges,
    total_charged,
    untraceable_pct,
    primary_payment_type,
    distinct_payment_methods,
    dispute_count,
    failure_count,
    account_lifespan_days,
    account_verification_status,
    accounts_on_shared_infra,
    is_cancelled,

    signal_confidence,
    'Untraceable Payment Methods'                           AS signal_name,
    'Account ' || account_id
        || ': ' || untraceable_pct::VARCHAR || '% of '
        || total_charges::VARCHAR || ' charges used untraceable methods ('
        || primary_payment_type || '). $'
        || ROUND(total_charged, 0)::VARCHAR || ' total. '
        || 'Account lifespan: ' || account_lifespan_days::VARCHAR || ' days. '
        || CASE WHEN account_verification_status = 'unverified'
           THEN 'Unverified account. ' ELSE '' END
        || CASE WHEN dispute_count > 0
           THEN dispute_count::VARCHAR || ' disputes filed. ' ELSE '' END
        || CASE WHEN accounts_on_shared_infra >= 2
           THEN 'Shares device/IP with ' || accounts_on_shared_infra::VARCHAR || ' accounts.'
           ELSE '' END                                      AS glass_box_verdict

FROM flagged_accounts
ORDER BY signal_confidence, total_charged DESC;

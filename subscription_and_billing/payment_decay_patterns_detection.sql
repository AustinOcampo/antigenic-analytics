-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: PAYMENT DECAY PATTERNS
-- =============================================================================
-- File:     payment_decay_patterns_detection.sql
-- Signal:   S05 of 10 — Subscription & Recurring Billing Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Payment methods that succeed for the trial period then conveniently fail
-- before the first real charge. This is a deliberate pattern: the user
-- provides a valid payment method to pass signup validation, uses the full
-- trial, then ensures the method declines when the paid period begins —
-- via prepaid cards with exact balances, virtual cards with spend limits,
-- or cancellation of the underlying card.
--
-- BEHAVIORAL TELL:
-- Legitimate payment failures are random — they happen at any billing cycle
-- and are usually resolved quickly (card expired, insufficient funds from
-- timing). Intentional payment decay is clustered at the trial-to-paid
-- transition: the method works for $0 or $1 auth during signup, processes
-- successfully during trial, then fails on the first real charge. The user
-- shows no attempt to update payment and often has already created the next
-- account.
--
-- DATA REQUIREMENTS:
-- Requires: account_id, charge_id, charge_amount, charge_date, charge_status,
--           payment_method_id, trial_end_date
-- Optional: payment_method_type, payment_method_created_at, retry_count,
--           account_created_at, device_id, ip_address
--
-- TUNING PARAMETERS:
-- * failure_window_days      — days after trial end to check for failure (default: 7)
-- * min_accounts             — minimum accounts with pattern to flag (default: 5)
-- * no_update_days           — days without payment update to confirm intent (default: 14)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $5K–$80K in avoided subscription revenue
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_accounts AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        created_at              AS account_created_at,        -- expected: TIMESTAMP_NTZ
        trial_end               AS trial_end_date,           -- expected: DATE / TIMESTAMP
        device_id               AS device_id,                -- expected: VARCHAR
        ip_address              AS ip_address,               -- expected: VARCHAR
        payment_method_id       AS payment_method_id,        -- expected: VARCHAR

    FROM your_account_table                                  -- << REPLACE WITH YOUR TABLE

),

normalized_charges AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        charge_id               AS charge_id,                -- expected: VARCHAR / STRING
        amount                  AS charge_amount,            -- expected: FLOAT / NUMBER
        charge_date             AS charge_date,              -- expected: DATE / TIMESTAMP
        status                  AS charge_status,            -- expected: VARCHAR ('succeeded','failed','declined')
        payment_method_id       AS payment_method_id,        -- expected: VARCHAR
        payment_method_type     AS payment_method_type,      -- expected: VARCHAR ('credit','debit','prepaid','virtual')
        retry_count             AS retry_count,              -- expected: INTEGER

    FROM your_charge_table                                   -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        7       AS failure_window_days,         -- first charge within 7 days of trial end
        5       AS min_accounts,                -- need cluster to confirm deliberate pattern
        14      AS no_update_days,              -- 14 days without payment update = no intent to resolve
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

-- Step 1: Identify accounts where first post-trial charge failed
first_paid_charge AS (
    SELECT
        a.account_id,
        a.trial_end_date,
        a.device_id,
        a.ip_address,
        a.payment_method_id                                 AS signup_payment_method,
        c.charge_id,
        c.charge_amount,
        c.charge_date,
        c.charge_status,
        c.payment_method_type,
        c.retry_count,
        DATEDIFF('day', a.trial_end_date, c.charge_date)   AS days_after_trial,
        ROW_NUMBER() OVER (
            PARTITION BY a.account_id
            ORDER BY c.charge_date ASC
        )                                                   AS charge_sequence
    FROM normalized_accounts a
    INNER JOIN normalized_charges c
        ON a.account_id = c.account_id
        AND c.charge_date >= a.trial_end_date
        AND c.charge_amount > 1                             -- exclude $0/$1 auth holds
    WHERE a.trial_end_date IS NOT NULL
      AND a.trial_end_date >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

trial_to_paid_failures AS (
    SELECT *
    FROM first_paid_charge
    WHERE charge_sequence = 1
      AND charge_status IN ('failed', 'declined')
      AND days_after_trial <= (SELECT failure_window_days FROM thresholds)
),

-- Step 2: Check if payment was ever updated after failure
payment_update_check AS (
    SELECT
        tpf.account_id,
        tpf.charge_date                                     AS failure_date,
        MAX(c2.charge_date)                                 AS next_successful_charge,
        CASE
            WHEN MAX(CASE WHEN c2.charge_status = 'succeeded' THEN c2.charge_date END) IS NULL
            THEN TRUE ELSE FALSE
        END                                                 AS never_resolved
    FROM trial_to_paid_failures tpf
    LEFT JOIN normalized_charges c2
        ON tpf.account_id = c2.account_id
        AND c2.charge_date > tpf.charge_date
        AND c2.charge_date <= DATEADD('day', (SELECT no_update_days FROM thresholds), tpf.charge_date)
    GROUP BY tpf.account_id, tpf.charge_date
),

-- Step 3: Enrich with account details
account_decay_profile AS (
    SELECT
        tpf.account_id,
        tpf.trial_end_date,
        tpf.charge_amount,
        tpf.charge_date,
        tpf.days_after_trial,
        tpf.payment_method_type,
        tpf.retry_count,
        tpf.device_id,
        tpf.ip_address,
        puc.never_resolved
    FROM trial_to_paid_failures tpf
    INNER JOIN payment_update_check puc
        ON tpf.account_id = puc.account_id
),

-- Step 4: Cluster by shared infrastructure
decay_clusters AS (
    SELECT
        a.account_id            AS account_a,
        b.account_id            AS account_b
    FROM account_decay_profile a
    INNER JOIN account_decay_profile b
        ON a.account_id < b.account_id
        AND (a.device_id = b.device_id OR a.ip_address = b.ip_address)
),

decay_cluster_seeds AS (
    SELECT account_a AS account_id, account_a AS cluster_root FROM decay_clusters
    UNION
    SELECT account_b AS account_id, account_a AS cluster_root FROM decay_clusters
),

decay_cluster_assignment AS (
    SELECT account_id, MIN(cluster_root) AS cluster_id
    FROM decay_cluster_seeds
    GROUP BY account_id
),

-- Step 5: Score individual accounts and clusters
flagged_accounts AS (
    SELECT
        adp.*,
        dca.cluster_id,
        COUNT(*) OVER (PARTITION BY dca.cluster_id)         AS cluster_size,
        CASE
            WHEN adp.never_resolved = TRUE
             AND dca.cluster_id IS NOT NULL
             AND COUNT(*) OVER (PARTITION BY dca.cluster_id) >= 5
                                                            THEN 'HIGH — Clustered Intentional Decay'
            WHEN adp.never_resolved = TRUE
             AND dca.cluster_id IS NOT NULL
             AND COUNT(*) OVER (PARTITION BY dca.cluster_id) >= (SELECT min_accounts FROM thresholds)
                                                            THEN 'HIGH — Shared Infra + Never Resolved'
            WHEN adp.never_resolved = TRUE
             AND adp.payment_method_type IN ('prepaid', 'virtual')
                                                            THEN 'MEDIUM — Prepaid/Virtual + Never Resolved'
            WHEN adp.never_resolved = TRUE
             AND adp.days_after_trial <= 1                   THEN 'MEDIUM — Immediate Post-Trial Failure'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM account_decay_profile adp
    LEFT JOIN decay_cluster_assignment dca
        ON adp.account_id = dca.account_id
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    account_id,
    trial_end_date,
    charge_amount,
    charge_date,
    days_after_trial,
    payment_method_type,
    never_resolved,
    cluster_id,
    cluster_size,

    signal_confidence,
    'Payment Decay Patterns'                                AS signal_name,
    'Account ' || account_id
        || ': first post-trial charge of $' || ROUND(charge_amount, 2)::VARCHAR
        || ' failed ' || days_after_trial::VARCHAR || ' days after trial ended. '
        || CASE WHEN never_resolved THEN 'Payment never resolved. ' ELSE 'Payment eventually resolved. ' END
        || CASE WHEN payment_method_type IN ('prepaid', 'virtual')
           THEN 'Payment method type: ' || payment_method_type || '. '
           ELSE '' END
        || CASE WHEN cluster_id IS NOT NULL
           THEN 'Part of ' || cluster_size::VARCHAR || '-account cluster sharing infrastructure.'
           ELSE 'No infrastructure cluster detected.' END   AS glass_box_verdict

FROM flagged_accounts
ORDER BY signal_confidence, cluster_size DESC NULLS LAST;

-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: CHURN-AND-RETURN CYCLING
-- =============================================================================
-- File:     churn_and_return_cycling_detection.sql
-- Signal:   S10 of 10 — Subscription & Recurring Billing Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Accounts that hit usage limits, churn, re-sign up under a new identity,
-- and repeat the cycle. These users treat the subscription as a series of
-- disposable accounts rather than a continuous relationship. Each new
-- account captures introductory pricing, free tier allowances, or trial
-- periods that were intended for genuinely new customers. The shared
-- infrastructure across "new" accounts reveals they are the same operator.
--
-- BEHAVIORAL TELL:
-- Legitimate churn is permanent or results in a single return. Cycling
-- churn shows a pattern: account active for a fixed duration (matching
-- a billing cycle or usage reset), cancellation, then a new account from
-- the same device/IP/payment fingerprint within days. The new account
-- immediately shows expert-level usage — no onboarding fumbling, no
-- feature discovery, just immediate productive use of exactly the same
-- features as the previous account.
--
-- DATA REQUIREMENTS:
-- Requires: account_id, account_created_at, account_cancelled_at,
--           subscription_plan, device_id, ip_address
-- Optional: payment_method_fingerprint, email_address, usage_first_24h_actions,
--           cancellation_reason, total_usage_actions, account_lifespan_days
--
-- TUNING PARAMETERS:
-- * min_cycle_count          — minimum churn-return cycles to flag (default: 2)
-- * max_gap_days             — days between cancel and new signup (default: 14)
-- * min_accounts_in_chain    — minimum accounts in chain to flag (default: 3)
-- * lookback_days            — analysis window (default: 365)
--
-- TYPICAL EXPOSURE: $10K–$150K in perpetual introductory pricing
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_accounts AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        created_at              AS account_created_at,        -- expected: TIMESTAMP_NTZ
        cancelled_at            AS account_cancelled_at,     -- expected: TIMESTAMP_NTZ (NULL if active)
        plan_name               AS subscription_plan,        -- expected: VARCHAR
        device_id               AS device_id,                -- expected: VARCHAR
        ip_address              AS ip_address,               -- expected: VARCHAR
        payment_fingerprint     AS payment_method_fingerprint, -- expected: VARCHAR
        email                   AS email_address,            -- expected: VARCHAR
        cancellation_reason     AS cancellation_reason,      -- expected: VARCHAR
        total_actions           AS total_usage_actions,      -- expected: INTEGER
        DATEDIFF('day', created_at,
                 COALESCE(cancelled_at, CURRENT_TIMESTAMP()))
                                                            AS account_lifespan_days

    FROM your_account_table                                  -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        2       AS min_cycle_count,             -- 2+ cycles = deliberate pattern
        14      AS max_gap_days,                -- new account within 14 days of cancellation = cycling
        3       AS min_accounts_in_chain,       -- need 3+ accounts to confirm chain
        365     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

accounts_in_scope AS (
    SELECT *
    FROM normalized_accounts
    WHERE account_created_at >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 1: Link accounts by shared infrastructure
account_links AS (
    SELECT
        a.account_id            AS account_a,
        b.account_id            AS account_b,
        a.account_cancelled_at  AS a_cancelled_at,
        b.account_created_at    AS b_created_at,
        DATEDIFF('day', a.account_cancelled_at, b.account_created_at)
                                                            AS days_between,
        CASE WHEN a.device_id IS NOT NULL AND a.device_id = b.device_id THEN 1 ELSE 0 END
      + CASE WHEN a.ip_address IS NOT NULL AND a.ip_address = b.ip_address THEN 1 ELSE 0 END
      + CASE WHEN a.payment_method_fingerprint IS NOT NULL
             AND a.payment_method_fingerprint = b.payment_method_fingerprint THEN 1 ELSE 0 END
                                                            AS shared_signals,
        ARRAY_CONSTRUCT_COMPACT(
            CASE WHEN a.device_id = b.device_id THEN 'DEVICE' END,
            CASE WHEN a.ip_address = b.ip_address THEN 'IP' END,
            CASE WHEN a.payment_method_fingerprint = b.payment_method_fingerprint THEN 'PAYMENT' END
        )                                                   AS shared_types
    FROM accounts_in_scope a
    INNER JOIN accounts_in_scope b
        ON a.account_id != b.account_id
        AND a.account_cancelled_at IS NOT NULL
        AND b.account_created_at > a.account_cancelled_at
        AND DATEDIFF('day', a.account_cancelled_at, b.account_created_at)
            <= (SELECT max_gap_days FROM thresholds)
    WHERE a.device_id = b.device_id
       OR a.ip_address = b.ip_address
       OR a.payment_method_fingerprint = b.payment_method_fingerprint
),

-- Step 2: Build chains
chain_seeds AS (
    SELECT account_a AS account_id, account_a AS chain_root FROM account_links WHERE shared_signals >= 1
    UNION
    SELECT account_b AS account_id, account_a AS chain_root FROM account_links WHERE shared_signals >= 1
),

chain_assignment AS (
    SELECT account_id, MIN(chain_root) AS chain_id
    FROM chain_seeds
    GROUP BY account_id
),

-- Step 3: Chain metrics
chain_metrics AS (
    SELECT
        ca.chain_id,
        COUNT(DISTINCT ca.account_id)                       AS chain_length,
        ARRAY_AGG(DISTINCT ca.account_id)                   AS chain_accounts,
        -- Account lifecycle patterns
        AVG(a.account_lifespan_days)                        AS avg_lifespan_days,
        STDDEV(a.account_lifespan_days)                     AS stddev_lifespan_days,
        MIN(a.account_created_at)                           AS chain_start,
        MAX(COALESCE(a.account_cancelled_at, CURRENT_TIMESTAMP()))
                                                            AS chain_end,
        DATEDIFF('day', MIN(a.account_created_at),
                 MAX(COALESCE(a.account_cancelled_at, CURRENT_TIMESTAMP())))
                                                            AS chain_span_days,
        -- Usage patterns
        AVG(a.total_usage_actions)                          AS avg_total_actions,
        -- Infrastructure
        COUNT(DISTINCT a.device_id)                         AS distinct_devices,
        COUNT(DISTINCT a.ip_address)                        AS distinct_ips,
        COUNT(DISTINCT a.payment_method_fingerprint)        AS distinct_payment_methods,
        COUNT(DISTINCT a.email_address)                     AS distinct_emails,
        -- Plan patterns
        COUNT(DISTINCT a.subscription_plan)                 AS distinct_plans,
        MODE(a.subscription_plan)                           AS most_common_plan,
        MODE(a.cancellation_reason)                         AS most_common_cancel_reason,
        -- How many accounts are currently active (last in chain)
        COUNT(CASE WHEN a.account_cancelled_at IS NULL THEN 1 END)
                                                            AS currently_active_count
    FROM chain_assignment ca
    INNER JOIN accounts_in_scope a
        ON ca.account_id = a.account_id
    GROUP BY ca.chain_id
),

-- Step 4: Score and flag
flagged_chains AS (
    SELECT
        cm.*,
        CASE
            WHEN cm.chain_length >= 5
             AND cm.distinct_devices <= 2
             AND cm.avg_lifespan_days <= 45                  THEN 'HIGH — Serial Account Churner (5+ accounts)'
            WHEN cm.chain_length >= (SELECT min_accounts_in_chain FROM thresholds)
             AND cm.stddev_lifespan_days <= 10
             AND cm.distinct_devices <= 2                    THEN 'HIGH — Consistent Cycle Pattern'
            WHEN cm.chain_length >= (SELECT min_accounts_in_chain FROM thresholds)
             AND cm.avg_lifespan_days <= 45                  THEN 'MEDIUM — Short-Lived Account Chain'
            WHEN cm.chain_length >= (SELECT min_accounts_in_chain FROM thresholds)
             AND cm.distinct_emails > cm.chain_length * 0.8  THEN 'MEDIUM — Identity Rotation Chain'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM chain_metrics cm
    CROSS JOIN thresholds t
    WHERE cm.chain_length >= t.min_accounts_in_chain
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    chain_id,
    chain_length,
    chain_accounts,
    avg_lifespan_days,
    stddev_lifespan_days,
    chain_span_days,
    distinct_devices,
    distinct_ips,
    distinct_payment_methods,
    distinct_emails,
    most_common_plan,
    most_common_cancel_reason,
    currently_active_count,
    avg_total_actions,

    signal_confidence,
    'Churn-and-Return Cycling'                              AS signal_name,
    'Chain of ' || chain_length::VARCHAR
        || ' accounts over ' || chain_span_days::VARCHAR || ' days. '
        || 'Avg lifespan: ' || ROUND(avg_lifespan_days, 0)::VARCHAR
        || ' days (stddev: ' || ROUND(COALESCE(stddev_lifespan_days, 0), 0)::VARCHAR || '). '
        || distinct_devices::VARCHAR || ' devices, '
        || distinct_ips::VARCHAR || ' IPs, '
        || distinct_emails::VARCHAR || ' emails, '
        || distinct_payment_methods::VARCHAR || ' payment methods. '
        || 'Most common plan: ' || most_common_plan || '. '
        || currently_active_count::VARCHAR
        || ' currently active.'                             AS glass_box_verdict

FROM flagged_chains
ORDER BY signal_confidence, chain_length DESC;

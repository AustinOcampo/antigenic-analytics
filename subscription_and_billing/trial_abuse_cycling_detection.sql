-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: TRIAL ABUSE CYCLING
-- =============================================================================
-- File:     trial_abuse_cycling_detection.sql
-- Signal:   S01 of 10 — Subscription & Recurring Billing Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Free trial signups from the same devices and payment fingerprints cycling
-- through new accounts endlessly. Trial abusers create a new identity for
-- every trial period — new email, sometimes new payment method — but reuse
-- the same device, IP, browser fingerprint, or partial card number. The
-- accounts are disposable; the infrastructure is persistent.
--
-- BEHAVIORAL TELL:
-- Legitimate trial users sign up once, explore the product, and either
-- convert or leave. Trial abusers show a manufacturing pattern: accounts
-- created in sequence, each active for exactly the trial duration, with
-- overlapping device or payment fingerprints. The trial-to-paid conversion
-- rate for these clusters approaches zero, and usage patterns are immediate
-- and heavy (they know exactly what they want because they've done it before).
--
-- DATA REQUIREMENTS:
-- Requires: account_id, account_created_at, subscription_plan, trial_start_date,
--           trial_end_date, converted_to_paid, device_id, ip_address
-- Optional: payment_method_fingerprint, email_domain, browser_fingerprint,
--           usage_first_24h_actions, cancellation_date
--
-- TUNING PARAMETERS:
-- * min_cluster_size         — minimum accounts sharing infra to flag (default: 3)
-- * trial_conversion_threshold — cluster conversion rate below which to flag (default: 10%)
-- * device_reuse_lookback_days — window to look for device reuse (default: 365)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $5K–$100K in perpetual free usage
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_accounts AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        created_at              AS account_created_at,        -- expected: TIMESTAMP_NTZ
        plan_name               AS subscription_plan,        -- expected: VARCHAR
        trial_start              AS trial_start_date,         -- expected: DATE / TIMESTAMP
        trial_end                AS trial_end_date,           -- expected: DATE / TIMESTAMP
        is_paid                  AS converted_to_paid,        -- expected: BOOLEAN
        device_id               AS device_id,                -- expected: VARCHAR
        ip_address              AS ip_address,               -- expected: VARCHAR
        payment_fingerprint     AS payment_method_fingerprint, -- expected: VARCHAR (last 4 + BIN hash, etc.)
        email_domain            AS email_domain,             -- expected: VARCHAR (domain portion only)
        cancelled_at            AS cancellation_date,        -- expected: TIMESTAMP_NTZ (NULL if active)

    FROM your_account_table                                  -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        3       AS min_cluster_size,            -- 3+ accounts on same device = cycling, not coincidence
        10.0    AS trial_conversion_threshold,  -- cluster conversion < 10% = no intent to pay
        365     AS device_reuse_lookback_days,  -- look back 1 year for device reuse patterns
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

accounts_in_scope AS (
    SELECT *
    FROM normalized_accounts
    WHERE account_created_at >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
      AND trial_start_date IS NOT NULL
),

-- Step 1: Link accounts by shared infrastructure
device_clusters AS (
    SELECT
        a.account_id            AS account_a,
        b.account_id            AS account_b,
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
        ON a.account_id < b.account_id
    WHERE a.device_id = b.device_id
       OR a.ip_address = b.ip_address
       OR a.payment_method_fingerprint = b.payment_method_fingerprint
),

-- Step 2: Build clusters (connected components via min ID)
cluster_seeds AS (
    SELECT account_a AS account_id, account_a AS cluster_root FROM device_clusters WHERE shared_signals >= 1
    UNION
    SELECT account_b AS account_id, account_a AS cluster_root FROM device_clusters WHERE shared_signals >= 1
),

cluster_assignment AS (
    SELECT
        account_id,
        MIN(cluster_root)                                   AS cluster_id
    FROM cluster_seeds
    GROUP BY account_id
),

-- Step 3: Compute cluster metrics
cluster_metrics AS (
    SELECT
        ca.cluster_id,
        COUNT(DISTINCT ca.account_id)                       AS cluster_size,
        ARRAY_AGG(DISTINCT ca.account_id)                   AS cluster_accounts,
        -- Trial behavior
        COUNT(CASE WHEN a.converted_to_paid = TRUE THEN 1 END)
                                                            AS paid_conversions,
        ROUND(100.0 * COUNT(CASE WHEN a.converted_to_paid = TRUE THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS conversion_rate_pct,
        -- Timing patterns
        MIN(a.account_created_at)                           AS first_account_created,
        MAX(a.account_created_at)                           AS last_account_created,
        DATEDIFF('day', MIN(a.account_created_at),
                 MAX(a.account_created_at))                 AS creation_span_days,
        AVG(DATEDIFF('day', a.trial_start_date, a.trial_end_date))
                                                            AS avg_trial_duration_days,
        -- Cancellation patterns
        COUNT(CASE WHEN a.cancellation_date IS NOT NULL THEN 1 END)
                                                            AS cancelled_count,
        AVG(CASE WHEN a.cancellation_date IS NOT NULL
            THEN DATEDIFF('day', a.trial_start_date, a.cancellation_date) END)
                                                            AS avg_days_to_cancel,
        -- Infrastructure
        COUNT(DISTINCT a.device_id)                         AS distinct_devices,
        COUNT(DISTINCT a.ip_address)                        AS distinct_ips,
        COUNT(DISTINCT a.email_domain)                      AS distinct_email_domains,
        COUNT(DISTINCT a.payment_method_fingerprint)        AS distinct_payment_methods
    FROM cluster_assignment ca
    INNER JOIN accounts_in_scope a
        ON ca.account_id = a.account_id
    GROUP BY ca.cluster_id
),

-- Step 4: Detect sequential trial patterns (one ends, next begins)
sequential_trials AS (
    SELECT
        ca.cluster_id,
        a.account_id,
        a.trial_start_date,
        a.trial_end_date,
        LEAD(a.trial_start_date) OVER (
            PARTITION BY ca.cluster_id ORDER BY a.trial_start_date
        )                                                   AS next_trial_start,
        DATEDIFF('day', a.trial_end_date,
                 LEAD(a.trial_start_date) OVER (
                     PARTITION BY ca.cluster_id ORDER BY a.trial_start_date
                 ))                                         AS days_between_trials
    FROM cluster_assignment ca
    INNER JOIN accounts_in_scope a
        ON ca.account_id = a.account_id
),

sequential_summary AS (
    SELECT
        cluster_id,
        COUNT(CASE WHEN days_between_trials BETWEEN 0 AND 7 THEN 1 END)
                                                            AS back_to_back_trials,
        AVG(CASE WHEN days_between_trials IS NOT NULL
            THEN days_between_trials END)                   AS avg_days_between_trials
    FROM sequential_trials
    GROUP BY cluster_id
),

-- Step 5: Score and flag
flagged_clusters AS (
    SELECT
        cm.*,
        COALESCE(ss.back_to_back_trials, 0)                 AS back_to_back_trials,
        COALESCE(ss.avg_days_between_trials, 0)             AS avg_days_between_trials,
        CASE
            WHEN cm.cluster_size >= 5
             AND cm.conversion_rate_pct = 0
             AND COALESCE(ss.back_to_back_trials, 0) >= 3   THEN 'HIGH — Serial Trial Farm'
            WHEN cm.cluster_size >= (SELECT min_cluster_size FROM thresholds)
             AND cm.conversion_rate_pct <= (SELECT trial_conversion_threshold FROM thresholds)
             AND COALESCE(ss.back_to_back_trials, 0) >= 1   THEN 'HIGH — Sequential Trial Cycling'
            WHEN cm.cluster_size >= (SELECT min_cluster_size FROM thresholds)
             AND cm.conversion_rate_pct <= (SELECT trial_conversion_threshold FROM thresholds)
                                                            THEN 'MEDIUM — Shared Infrastructure + No Conversion'
            WHEN cm.cluster_size >= (SELECT min_cluster_size FROM thresholds)
             AND cm.distinct_devices <= 2                    THEN 'MEDIUM — Device Reuse Cluster'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM cluster_metrics cm
    LEFT JOIN sequential_summary ss
        ON cm.cluster_id = ss.cluster_id
    CROSS JOIN thresholds t
    WHERE cm.cluster_size >= t.min_cluster_size
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    cluster_id,
    cluster_size,
    cluster_accounts,
    conversion_rate_pct,
    paid_conversions,
    back_to_back_trials,
    avg_days_between_trials,
    creation_span_days,
    distinct_devices,
    distinct_ips,
    distinct_email_domains,
    distinct_payment_methods,
    avg_days_to_cancel,

    signal_confidence,
    'Trial Abuse Cycling'                                   AS signal_name,
    'Cluster of ' || cluster_size::VARCHAR
        || ' trial accounts sharing infrastructure (cluster: '
        || cluster_id::VARCHAR || '). Conversion rate: '
        || conversion_rate_pct::VARCHAR || '%. '
        || back_to_back_trials::VARCHAR || ' back-to-back trial sequences. '
        || 'Created over ' || creation_span_days::VARCHAR || ' days. '
        || distinct_devices::VARCHAR || ' devices, '
        || distinct_ips::VARCHAR || ' IPs, '
        || distinct_payment_methods::VARCHAR
        || ' payment methods.'                              AS glass_box_verdict

FROM flagged_clusters
ORDER BY signal_confidence, cluster_size DESC;

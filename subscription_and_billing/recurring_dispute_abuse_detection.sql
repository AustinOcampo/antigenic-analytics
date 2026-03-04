-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: RECURRING DISPUTE ABUSE
-- =============================================================================
-- File:     recurring_dispute_abuse_detection.sql
-- Signal:   S02 of 10 — Subscription & Recurring Billing Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Users disputing recurring charges months into a subscription they actively
-- used. Unlike legitimate billing disputes, these users consumed the service
-- throughout the billing period — logging in, using features, downloading
-- content — then filed chargebacks claiming the charge was unauthorized or
-- the service was not as described. The usage data contradicts the dispute
-- narrative.
--
-- BEHAVIORAL TELL:
-- Legitimate dispute filers show minimal or no usage before the disputed
-- charge. Abusers show sustained, active usage right up until the dispute
-- filing date. They often dispute multiple billing cycles retroactively,
-- extracting months of free service. The gap between last active usage and
-- dispute filing is near zero — they used the product yesterday and
-- disputed the charge today.
--
-- DATA REQUIREMENTS:
-- Requires: account_id, charge_id, charge_amount, charge_date, charge_status,
--           dispute_date, dispute_reason, last_login_date
-- Optional: login_count_30d, feature_usage_score, content_downloads,
--           subscription_start_date, billing_cycle_number
--
-- TUNING PARAMETERS:
-- * min_usage_days_before_dispute — active days in 30d before dispute (default: 10)
-- * min_dispute_amount       — minimum disputed amount to surface (default: $50)
-- * multi_cycle_dispute_flag — disputes spanning 2+ cycles to flag (default: 2)
-- * lookback_days            — analysis window (default: 365)
--
-- TYPICAL EXPOSURE: $10K–$200K in chargebacks + processor penalties
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_charges AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        charge_id               AS charge_id,                -- expected: VARCHAR / STRING
        amount                  AS charge_amount,            -- expected: FLOAT / NUMBER
        charge_date             AS charge_date,              -- expected: DATE / TIMESTAMP
        status                  AS charge_status,            -- expected: VARCHAR ('paid','disputed','refunded')
        dispute_date            AS dispute_date,             -- expected: DATE / TIMESTAMP (NULL if no dispute)
        dispute_reason          AS dispute_reason,           -- expected: VARCHAR (NULL if no dispute)
        billing_cycle           AS billing_cycle_number,     -- expected: INTEGER
        subscription_start      AS subscription_start_date,  -- expected: DATE / TIMESTAMP

    FROM your_charge_table                                   -- << REPLACE WITH YOUR TABLE

),

normalized_usage AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        activity_date           AS activity_date,            -- expected: DATE
        login_count             AS daily_logins,             -- expected: INTEGER
        actions_count           AS daily_actions,            -- expected: INTEGER
        downloads               AS daily_downloads,          -- expected: INTEGER

    FROM your_usage_table                                    -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        10      AS min_usage_days_before_dispute, -- 10+ active days in 30d before dispute = heavy user
        50      AS min_dispute_amount,            -- filter trivial disputes
        2       AS multi_cycle_dispute_flag,      -- disputing 2+ cycles = systematic extraction
        365     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

disputes_in_scope AS (
    SELECT *
    FROM normalized_charges
    WHERE dispute_date IS NOT NULL
      AND dispute_date >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 1: Compute usage in the 30 days before each dispute
pre_dispute_usage AS (
    SELECT
        d.account_id,
        d.charge_id,
        d.dispute_date,
        d.charge_amount,
        d.dispute_reason,
        d.billing_cycle_number,
        d.subscription_start_date,
        COUNT(DISTINCT u.activity_date)                     AS active_days_30d,
        SUM(u.daily_logins)                                 AS total_logins_30d,
        SUM(u.daily_actions)                                AS total_actions_30d,
        SUM(u.daily_downloads)                              AS total_downloads_30d,
        MAX(u.activity_date)                                AS last_active_date,
        DATEDIFF('day', MAX(u.activity_date), d.dispute_date)
                                                            AS days_since_last_activity
    FROM disputes_in_scope d
    LEFT JOIN normalized_usage u
        ON d.account_id = u.account_id
        AND u.activity_date BETWEEN DATEADD('day', -30, d.dispute_date) AND d.dispute_date
    GROUP BY d.account_id, d.charge_id, d.dispute_date,
             d.charge_amount, d.dispute_reason,
             d.billing_cycle_number, d.subscription_start_date
),

-- Step 2: Account-level dispute patterns
account_dispute_stats AS (
    SELECT
        account_id,
        COUNT(DISTINCT charge_id)                           AS total_disputes,
        SUM(charge_amount)                                  AS total_disputed_amount,
        AVG(charge_amount)                                  AS avg_dispute_amount,
        MIN(dispute_date)                                   AS first_dispute_date,
        MAX(dispute_date)                                   AS last_dispute_date,
        MAX(billing_cycle_number) - MIN(billing_cycle_number) + 1
                                                            AS billing_cycles_disputed,
        MIN(subscription_start_date)                        AS subscription_start,
        DATEDIFF('month', MIN(subscription_start_date), MIN(dispute_date))
                                                            AS months_before_first_dispute,
        -- Aggregate pre-dispute usage
        AVG(active_days_30d)                                AS avg_active_days_pre_dispute,
        AVG(total_logins_30d)                               AS avg_logins_pre_dispute,
        AVG(total_actions_30d)                              AS avg_actions_pre_dispute,
        MIN(days_since_last_activity)                       AS min_days_since_activity,
        MODE(dispute_reason)                                AS primary_dispute_reason
    FROM pre_dispute_usage
    GROUP BY account_id
),

-- Step 3: Score and flag
flagged_accounts AS (
    SELECT
        ads.*,
        CASE
            WHEN ads.total_disputes >= 3
             AND ads.avg_active_days_pre_dispute >= 20
             AND ads.min_days_since_activity <= 2            THEN 'HIGH — Serial Disputer with Heavy Usage'
            WHEN ads.billing_cycles_disputed >= (SELECT multi_cycle_dispute_flag FROM thresholds)
             AND ads.avg_active_days_pre_dispute >= (SELECT min_usage_days_before_dispute FROM thresholds)
                                                            THEN 'HIGH — Multi-Cycle Dispute + Active Usage'
            WHEN ads.avg_active_days_pre_dispute >= (SELECT min_usage_days_before_dispute FROM thresholds)
             AND ads.min_days_since_activity <= 3
             AND ads.total_disputed_amount >= 100            THEN 'MEDIUM — Active User Filing Disputes'
            WHEN ads.total_disputes >= 2
             AND ads.months_before_first_dispute >= 3        THEN 'MEDIUM — Late-Stage Retroactive Disputes'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM account_dispute_stats ads
    CROSS JOIN thresholds t
    WHERE ads.total_disputed_amount >= t.min_dispute_amount
      AND (
          ads.avg_active_days_pre_dispute >= t.min_usage_days_before_dispute
          OR ads.total_disputes >= t.multi_cycle_dispute_flag
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    account_id,
    total_disputes,
    total_disputed_amount,
    billing_cycles_disputed,
    avg_active_days_pre_dispute,
    avg_logins_pre_dispute,
    avg_actions_pre_dispute,
    min_days_since_activity,
    months_before_first_dispute,
    primary_dispute_reason,
    subscription_start,

    signal_confidence,
    'Recurring Dispute Abuse'                               AS signal_name,
    'Account ' || account_id
        || ' disputed ' || total_disputes::VARCHAR
        || ' charges totaling $' || ROUND(total_disputed_amount, 0)::VARCHAR
        || ' across ' || billing_cycles_disputed::VARCHAR || ' billing cycles. '
        || 'Avg ' || ROUND(avg_active_days_pre_dispute, 0)::VARCHAR
        || ' active days in 30d before each dispute. '
        || ROUND(avg_logins_pre_dispute, 0)::VARCHAR || ' avg logins, '
        || ROUND(avg_actions_pre_dispute, 0)::VARCHAR || ' avg actions pre-dispute. '
        || 'Last activity ' || min_days_since_activity::VARCHAR
        || ' days before filing. Reason: "'
        || COALESCE(primary_dispute_reason, 'N/A')
        || '".'                                             AS glass_box_verdict

FROM flagged_accounts
ORDER BY signal_confidence, total_disputed_amount DESC;

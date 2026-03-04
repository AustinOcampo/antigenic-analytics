-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: TIER MANIPULATION
-- =============================================================================
-- File:     tier_manipulation_detection.sql
-- Signal:   S06 of 10 — Subscription & Recurring Billing Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Accounts downgrading and upgrading in patterns designed to exploit billing
-- gaps between tiers. Manipulators discover that downgrading mid-cycle
-- retains premium access until the cycle ends, or that upgrading triggers
-- a prorated credit they can exploit by immediately downgrading again.
-- The pattern is a sawtooth of plan changes that extracts maximum value
-- at minimum price.
--
-- BEHAVIORAL TELL:
-- Legitimate plan changes are rare — a user might upgrade once, or downgrade
-- after a budget cut. Manipulators show oscillation: upgrade, use premium
-- features heavily for a few days, downgrade before the next billing cycle,
-- repeat. The frequency of plan changes per account is the primary indicator,
-- combined with usage patterns that spike during upgrade windows.
--
-- DATA REQUIREMENTS:
-- Requires: account_id, plan_change_id, old_plan, new_plan, change_timestamp,
--           old_price, new_price
-- Optional: billing_cycle_day, usage_during_upgrade, proration_credit_amount,
--           change_reason
--
-- TUNING PARAMETERS:
-- * min_plan_changes         — minimum plan changes to flag (default: 4)
-- * oscillation_threshold    — down-up or up-down cycles to flag (default: 2)
-- * change_frequency_days    — avg days between changes below which to flag (default: 30)
-- * lookback_days            — analysis window (default: 365)
--
-- TYPICAL EXPOSURE: $5K–$75K in tier arbitrage per account cluster
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_plan_changes AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        change_id               AS plan_change_id,           -- expected: VARCHAR / STRING
        old_plan                AS old_plan,                 -- expected: VARCHAR
        new_plan                AS new_plan,                 -- expected: VARCHAR
        changed_at              AS change_timestamp,         -- expected: TIMESTAMP_NTZ
        old_price               AS old_price,                -- expected: FLOAT / NUMBER (monthly)
        new_price               AS new_price,                -- expected: FLOAT / NUMBER (monthly)
        proration_credit        AS proration_credit_amount,  -- expected: FLOAT (NULL if none)
        change_reason           AS change_reason,            -- expected: VARCHAR

    FROM your_plan_change_table                              -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        4       AS min_plan_changes,            -- 4+ plan changes in the window = unusual
        2       AS oscillation_threshold,       -- 2+ up/down cycles = deliberate exploitation
        30      AS change_frequency_days,       -- changing plans more than monthly = gaming
        365     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

changes_in_scope AS (
    SELECT *
    FROM normalized_plan_changes
    WHERE change_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 1: Classify each change as upgrade or downgrade
classified_changes AS (
    SELECT
        *,
        CASE
            WHEN new_price > old_price THEN 'UPGRADE'
            WHEN new_price < old_price THEN 'DOWNGRADE'
            ELSE 'LATERAL'
        END                                                 AS change_direction,
        new_price - old_price                               AS price_delta,
        LAG(change_timestamp) OVER (
            PARTITION BY account_id ORDER BY change_timestamp
        )                                                   AS prev_change_timestamp,
        DATEDIFF('day',
            LAG(change_timestamp) OVER (PARTITION BY account_id ORDER BY change_timestamp),
            change_timestamp
        )                                                   AS days_since_last_change
    FROM changes_in_scope
),

-- Step 2: Detect oscillation patterns (upgrade followed by downgrade or vice versa)
oscillation_detection AS (
    SELECT
        *,
        CASE
            WHEN change_direction = 'UPGRADE'
             AND LEAD(change_direction) OVER (PARTITION BY account_id ORDER BY change_timestamp) = 'DOWNGRADE'
            THEN 1
            WHEN change_direction = 'DOWNGRADE'
             AND LEAD(change_direction) OVER (PARTITION BY account_id ORDER BY change_timestamp) = 'UPGRADE'
            THEN 1
            ELSE 0
        END                                                 AS is_oscillation
    FROM classified_changes
),

-- Step 3: Account-level metrics
account_manipulation_stats AS (
    SELECT
        account_id,
        COUNT(*)                                            AS total_plan_changes,
        COUNT(CASE WHEN change_direction = 'UPGRADE' THEN 1 END)
                                                            AS upgrade_count,
        COUNT(CASE WHEN change_direction = 'DOWNGRADE' THEN 1 END)
                                                            AS downgrade_count,
        SUM(is_oscillation)                                 AS oscillation_cycles,
        AVG(days_since_last_change)                         AS avg_days_between_changes,
        MIN(days_since_last_change)                         AS min_days_between_changes,
        SUM(COALESCE(proration_credit_amount, 0))           AS total_proration_credits,
        SUM(CASE WHEN price_delta < 0 THEN ABS(price_delta) ELSE 0 END)
                                                            AS total_monthly_savings,
        MIN(change_timestamp)                               AS first_change,
        MAX(change_timestamp)                               AS last_change,
        DATEDIFF('day', MIN(change_timestamp),
                 MAX(change_timestamp))                     AS change_span_days,
        MODE(new_plan)                                      AS most_frequent_destination
    FROM oscillation_detection
    GROUP BY account_id
),

-- Step 4: Score and flag
flagged_accounts AS (
    SELECT
        ams.*,
        CASE
            WHEN ams.oscillation_cycles >= 4
             AND ams.avg_days_between_changes <= 14          THEN 'HIGH — Rapid Oscillation Pattern'
            WHEN ams.oscillation_cycles >= (SELECT oscillation_threshold FROM thresholds)
             AND ams.total_proration_credits > 0             THEN 'HIGH — Oscillation + Proration Exploitation'
            WHEN ams.total_plan_changes >= 6
             AND ams.avg_days_between_changes <= (SELECT change_frequency_days FROM thresholds)
                                                            THEN 'MEDIUM — Frequent Plan Changes'
            WHEN ams.oscillation_cycles >= (SELECT oscillation_threshold FROM thresholds)
                                                            THEN 'MEDIUM — Oscillation Pattern Detected'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM account_manipulation_stats ams
    CROSS JOIN thresholds t
    WHERE ams.total_plan_changes >= t.min_plan_changes
      AND (
          ams.oscillation_cycles >= t.oscillation_threshold
          OR ams.avg_days_between_changes <= t.change_frequency_days
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    account_id,
    total_plan_changes,
    upgrade_count,
    downgrade_count,
    oscillation_cycles,
    avg_days_between_changes,
    min_days_between_changes,
    total_proration_credits,
    total_monthly_savings,
    change_span_days,
    most_frequent_destination,

    signal_confidence,
    'Tier Manipulation'                                     AS signal_name,
    'Account ' || account_id
        || ': ' || total_plan_changes::VARCHAR || ' plan changes in '
        || change_span_days::VARCHAR || ' days ('
        || upgrade_count::VARCHAR || ' upgrades, '
        || downgrade_count::VARCHAR || ' downgrades). '
        || oscillation_cycles::VARCHAR || ' oscillation cycles. '
        || 'Avg ' || ROUND(avg_days_between_changes, 0)::VARCHAR
        || ' days between changes. '
        || CASE WHEN total_proration_credits > 0
           THEN '$' || ROUND(total_proration_credits, 0)::VARCHAR || ' in proration credits extracted. '
           ELSE '' END
        || 'Most frequent plan: '
        || most_frequent_destination || '.'                  AS glass_box_verdict

FROM flagged_accounts
ORDER BY signal_confidence, oscillation_cycles DESC;

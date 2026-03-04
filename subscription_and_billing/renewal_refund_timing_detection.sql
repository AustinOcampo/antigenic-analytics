-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: RENEWAL REFUND TIMING
-- =============================================================================
-- File:     renewal_refund_timing_detection.sql
-- Signal:   S07 of 10 — Subscription & Recurring Billing Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Refund requests clustered around renewal dates from users who consumed
-- the full billing period. These users wait until their subscription renews,
-- immediately request a refund claiming they forgot to cancel, retain access
-- for the refund processing window, and repeat the cycle. The refund is
-- approved because the policy allows it — but the pattern reveals intent.
--
-- BEHAVIORAL TELL:
-- Legitimate "forgot to cancel" refunds happen once. The user is surprised,
-- asks for a refund, and either cancels or continues. Abusers show a pattern:
-- refund requests within 24-48 hours of every renewal, full usage in the
-- prior period, and often a re-subscription shortly after at a lower rate
-- or through a promo. The timing precision is the tell — they didn't forget.
--
-- DATA REQUIREMENTS:
-- Requires: account_id, charge_id, charge_amount, charge_date,
--           refund_request_date, refund_status, refund_reason
-- Optional: usage_days_in_period, last_login_before_refund,
--           re_subscribed_date, re_subscribed_plan
--
-- TUNING PARAMETERS:
-- * refund_window_hours      — hours after renewal to flag refund request (default: 72)
-- * min_usage_days           — active days in prior period to confirm consumption (default: 15)
-- * repeat_refund_threshold  — number of renewal refunds to flag (default: 2)
-- * lookback_days            — analysis window (default: 365)
--
-- TYPICAL EXPOSURE: $5K–$100K in refunded but consumed service
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_charges AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        charge_id               AS charge_id,                -- expected: VARCHAR / STRING
        amount                  AS charge_amount,            -- expected: FLOAT / NUMBER
        charge_date             AS charge_date,              -- expected: TIMESTAMP_NTZ
        billing_period_start    AS period_start,             -- expected: DATE
        billing_period_end      AS period_end,               -- expected: DATE
        refund_requested_at     AS refund_request_date,      -- expected: TIMESTAMP_NTZ (NULL if no refund)
        refund_status           AS refund_status,            -- expected: VARCHAR ('approved','denied',NULL)
        refund_reason           AS refund_reason,            -- expected: VARCHAR

    FROM your_charge_table                                   -- << REPLACE WITH YOUR TABLE

),

normalized_usage AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        activity_date           AS activity_date,            -- expected: DATE
        login_count             AS daily_logins,             -- expected: INTEGER

    FROM your_usage_table                                    -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        72      AS refund_window_hours,         -- refund within 72 hrs of charge = "forgot to cancel" claim
        15      AS min_usage_days,              -- 15+ active days in billing period = full consumption
        2       AS repeat_refund_threshold,     -- 2+ renewal refunds = pattern, not accident
        365     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

charges_in_scope AS (
    SELECT *
    FROM normalized_charges
    WHERE charge_date >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 1: Identify renewal charges with quick refund requests
renewal_refunds AS (
    SELECT
        c.*,
        DATEDIFF('hour', c.charge_date, c.refund_request_date)
                                                            AS hours_to_refund_request
    FROM charges_in_scope c
    WHERE c.refund_request_date IS NOT NULL
      AND DATEDIFF('hour', c.charge_date, c.refund_request_date)
          <= (SELECT refund_window_hours FROM thresholds)
),

-- Step 2: Compute usage in the billing period before the refund
period_usage AS (
    SELECT
        rr.account_id,
        rr.charge_id,
        rr.period_start,
        rr.period_end,
        COUNT(DISTINCT u.activity_date)                     AS active_days_in_period,
        SUM(u.daily_logins)                                 AS total_logins_in_period,
        MAX(u.activity_date)                                AS last_active_in_period,
        DATEDIFF('day', MAX(u.activity_date), rr.refund_request_date)
                                                            AS days_inactive_before_refund
    FROM renewal_refunds rr
    LEFT JOIN normalized_usage u
        ON rr.account_id = u.account_id
        AND u.activity_date BETWEEN rr.period_start AND rr.period_end
    GROUP BY rr.account_id, rr.charge_id, rr.period_start, rr.period_end, rr.refund_request_date
),

-- Step 3: Account-level refund pattern
account_refund_stats AS (
    SELECT
        rr.account_id,
        COUNT(DISTINCT rr.charge_id)                        AS renewal_refund_count,
        SUM(rr.charge_amount)                               AS total_refunded_amount,
        AVG(rr.hours_to_refund_request)                     AS avg_hours_to_request,
        MIN(rr.hours_to_refund_request)                     AS min_hours_to_request,
        AVG(pu.active_days_in_period)                       AS avg_active_days_per_period,
        AVG(pu.total_logins_in_period)                      AS avg_logins_per_period,
        AVG(pu.days_inactive_before_refund)                 AS avg_days_inactive_before_refund,
        COUNT(CASE WHEN rr.refund_status = 'approved' THEN 1 END)
                                                            AS approved_refund_count,
        MODE(rr.refund_reason)                              AS primary_refund_reason
    FROM renewal_refunds rr
    LEFT JOIN period_usage pu
        ON rr.account_id = pu.account_id AND rr.charge_id = pu.charge_id
    GROUP BY rr.account_id
),

-- Step 4: Score and flag
flagged_accounts AS (
    SELECT
        ars.*,
        CASE
            WHEN ars.renewal_refund_count >= 3
             AND ars.avg_active_days_per_period >= 20
             AND ars.avg_hours_to_request <= 24              THEN 'HIGH — Serial Renewal Refund Abuser'
            WHEN ars.renewal_refund_count >= (SELECT repeat_refund_threshold FROM thresholds)
             AND ars.avg_active_days_per_period >= (SELECT min_usage_days FROM thresholds)
                                                            THEN 'HIGH — Repeat Refund + Full Usage'
            WHEN ars.renewal_refund_count >= (SELECT repeat_refund_threshold FROM thresholds)
             AND ars.avg_hours_to_request <= 48              THEN 'MEDIUM — Repeat Quick Refund Requests'
            WHEN ars.avg_active_days_per_period >= (SELECT min_usage_days FROM thresholds)
             AND ars.total_refunded_amount >= 100            THEN 'MEDIUM — High Usage + Refund'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM account_refund_stats ars
    CROSS JOIN thresholds t
    WHERE ars.renewal_refund_count >= t.repeat_refund_threshold
       OR (ars.avg_active_days_per_period >= t.min_usage_days AND ars.total_refunded_amount >= 100)
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    account_id,
    renewal_refund_count,
    total_refunded_amount,
    approved_refund_count,
    avg_hours_to_request,
    avg_active_days_per_period,
    avg_logins_per_period,
    avg_days_inactive_before_refund,
    primary_refund_reason,

    signal_confidence,
    'Renewal Refund Timing'                                 AS signal_name,
    'Account ' || account_id
        || ': ' || renewal_refund_count::VARCHAR || ' refund requests within '
        || ROUND(avg_hours_to_request, 0)::VARCHAR || ' avg hours of renewal. $'
        || ROUND(total_refunded_amount, 0)::VARCHAR || ' total refunded ('
        || approved_refund_count::VARCHAR || ' approved). '
        || 'Avg ' || ROUND(avg_active_days_per_period, 0)::VARCHAR
        || ' active days per billing period ('
        || ROUND(avg_logins_per_period, 0)::VARCHAR || ' avg logins). '
        || 'Reason: "' || COALESCE(primary_refund_reason, 'N/A')
        || '".'                                             AS glass_box_verdict

FROM flagged_accounts
ORDER BY signal_confidence, total_refunded_amount DESC;

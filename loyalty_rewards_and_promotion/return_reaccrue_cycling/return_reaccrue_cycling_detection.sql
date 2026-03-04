-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: RETURN + REACCRUE CYCLING
-- =============================================================================
-- File:     return_reaccrue_cycling_detection.sql
-- Signal:   L10 of 10 — Loyalty & Rewards
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Members who purchase to earn points, redeem those points, then return
-- the original purchase — effectively keeping the redeemed value while
-- recovering the purchase price. This exploits a timing gap in how most
-- loyalty programs handle return processing: the purchase earns points
-- immediately, redemption is instant, but the return credit and point
-- reversal may be processed separately or incompletely.
--
-- THE CYCLE:
--   1. Member purchases $200 item → earns 2,000 points
--   2. Member redeems 2,000 points for $20 gift card
--   3. Member returns $200 item → receives $200 refund
--   4. Net result: $20 gift card obtained for free
--   Repeat at scale = systematic extraction
--
-- BEHAVIORAL TELL:
-- The timing signature is distinctive: purchase → redemption → return
-- in a compressed window, often with the redemption occurring between
-- the purchase and the return. Members who repeat this cycle show an
-- abnormal correlation between redemption events and subsequent returns.
--
-- DATA REQUIREMENTS:
-- Requires: member_id, transaction_id, transaction_amount, transaction_status,
--           accrual_timestamp, points_earned, redemption_timestamp,
--           redemption_value, return_timestamp
--
-- TUNING PARAMETERS:
-- * cycle_window_days        — days for purchase→redeem→return cycle (default: 30)
-- * min_cycle_count          — minimum cycles to flag pattern (default: 2)
-- * min_extracted_value      — minimum total extracted value (default: $50)
--
-- TYPICAL EXPOSURE: $10,000 — $100,000
-- =============================================================================

WITH normalized_purchases AS (
    SELECT
        transaction_id          AS transaction_id,
        member_id               AS member_id,
        transaction_amount      AS transaction_amount,
        created_at              AS purchase_timestamp,
        returned_at             AS return_timestamp,        -- NULL if not returned
        CASE WHEN returned_at IS NOT NULL THEN 1 ELSE 0 END AS was_returned
    FROM your_orders_table          -- << CHANGE THIS
    WHERE created_at >= DATEADD('year', -1, CURRENT_DATE)
),

normalized_accruals AS (
    SELECT
        member_id,
        transaction_id,
        points_earned,
        accrual_timestamp
    FROM your_accrual_ledger_table  -- << CHANGE THIS
    WHERE accrual_reason = 'purchase'
),

normalized_redemptions AS (
    SELECT
        member_id,
        redemption_value,
        redemption_timestamp
    FROM your_redemption_ledger_table   -- << CHANGE THIS
),

thresholds AS (
    SELECT
        30      AS cycle_window_days,
        2       AS min_cycle_count,
        50      AS min_extracted_value
),

-- Join purchases to accruals
purchase_accruals AS (
    SELECT
        p.member_id,
        p.transaction_id,
        p.transaction_amount,
        p.purchase_timestamp,
        p.return_timestamp,
        p.was_returned,
        a.points_earned,
        a.accrual_timestamp
    FROM normalized_purchases p
    JOIN normalized_accruals a
        ON  p.transaction_id = a.transaction_id
        AND p.member_id = a.member_id
),

-- For each purchase, find redemptions that occurred BETWEEN purchase and return
cycles AS (
    SELECT
        pa.member_id,
        pa.transaction_id,
        pa.transaction_amount,
        pa.purchase_timestamp,
        pa.return_timestamp,
        pa.points_earned,
        r.redemption_value,
        r.redemption_timestamp,
        DATEDIFF('day', pa.purchase_timestamp, r.redemption_timestamp)
                                                        AS days_to_redemption,
        DATEDIFF('day', r.redemption_timestamp, pa.return_timestamp)
                                                        AS days_redemption_to_return
    FROM purchase_accruals pa
    JOIN normalized_redemptions r
        ON  pa.member_id = r.member_id
        -- Redemption happened AFTER purchase
        AND r.redemption_timestamp >= pa.purchase_timestamp
        -- Return happened AFTER redemption
        AND pa.return_timestamp >= r.redemption_timestamp
    CROSS JOIN thresholds t
    WHERE
        pa.was_returned = 1
        AND DATEDIFF('day', pa.purchase_timestamp, pa.return_timestamp)
            <= t.cycle_window_days
),

member_cycle_summary AS (
    SELECT
        member_id,
        COUNT(DISTINCT transaction_id)                  AS cycle_count,
        SUM(redemption_value)                           AS total_extracted_value,
        SUM(transaction_amount)                         AS total_purchase_amount_returned,
        AVG(days_to_redemption)                         AS avg_days_purchase_to_redemption,
        AVG(days_redemption_to_return)                  AS avg_days_redemption_to_return,
        MIN(purchase_timestamp)                         AS first_cycle_date,
        MAX(return_timestamp)                           AS last_cycle_date
    FROM cycles
    GROUP BY 1
)

SELECT
    member_id,
    cycle_count,
    total_extracted_value,
    total_purchase_amount_returned,
    ROUND(avg_days_purchase_to_redemption, 1)           AS avg_days_to_redeem,
    ROUND(avg_days_redemption_to_return, 1)             AS avg_days_to_return,
    first_cycle_date,
    last_cycle_date,

    CASE
        WHEN cycle_count >= 5                           THEN 'HIGH — Systematic Cycling'
        WHEN cycle_count >= t.min_cycle_count
         AND total_extracted_value >= 100               THEN 'HIGH — Confirmed Pattern'
        WHEN cycle_count >= t.min_cycle_count           THEN 'MEDIUM — Repeat Cycle'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'Return + Reaccrue Cycling'                         AS signal_name,
    'Member ' || member_id
        || ' completed ' || cycle_count::VARCHAR
        || ' purchase→redeem→return cycles, extracting $'
        || ROUND(total_extracted_value, 0)::VARCHAR
        || ' in redemption value while returning $'
        || ROUND(total_purchase_amount_returned, 0)::VARCHAR
        || ' in merchandise. Average time from purchase to redemption: '
        || ROUND(avg_days_purchase_to_redemption, 1)::VARCHAR || ' days.'
                                                        AS glass_box_verdict

FROM member_cycle_summary
CROSS JOIN thresholds t
WHERE
    cycle_count >= t.min_cycle_count
    AND total_extracted_value >= t.min_extracted_value

ORDER BY signal_confidence, total_extracted_value DESC;

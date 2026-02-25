-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: POINT FARMING
-- =============================================================================
-- File:     point_farming_detection.sql
-- Signal:   L01 of 10 — Loyalty & Rewards
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Members accruing points at rates that are statistically inconsistent with
-- their spend profile, tenure, or peer group — indicating manufactured
-- transactions, exploitation of bonus multipliers, or systematic gaming
-- of accrual rules. Point farmers treat your loyalty program as an
-- arbitrage opportunity rather than a customer retention mechanism.
--
-- BEHAVIORAL TELL:
-- Legitimate members accrue points organically — spending varies, accrual
-- follows spend, and the ratio between dollars spent and points earned
-- stays within a predictable band. Point farmers show an abnormal
-- points-to-spend ratio, often concentrated in specific accrual categories
-- or during bonus windows, with spend patterns that don't match what a
-- real customer purchasing those goods would look like.
--
-- DATA REQUIREMENTS:
-- Requires: member_id, accrual_amount_points, transaction_amount,
--           accrual_timestamp, accrual_reason, accrual_category
--
-- TUNING PARAMETERS:
-- * pts_per_dollar_threshold   — flag if member's ratio exceeds X (default: 3x peer avg)
-- * min_accrual_events         — minimum events before flagging (default: 10)
-- * min_points_farmed          — minimum excess points to surface (default: 5,000)
-- * lookback_days              — analysis window (default: 180 days)
--
-- TYPICAL EXPOSURE: $10,000 — $200,000
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_accruals AS (

    SELECT
        member_id               AS member_id,               -- expected: VARCHAR
        points_earned           AS points_earned,           -- expected: FLOAT
        transaction_amount      AS transaction_amount,      -- expected: FLOAT (spend that drove accrual)
        accrual_timestamp       AS accrual_timestamp,       -- expected: TIMESTAMP_NTZ
        accrual_reason          AS accrual_reason,          -- expected: VARCHAR ('purchase','bonus','referral')
        accrual_category        AS accrual_category         -- expected: VARCHAR (merchant/product category)

    FROM your_accrual_ledger_table  -- << CHANGE THIS

    WHERE
        accrual_timestamp >= DATEADD('day', -180, CURRENT_DATE)
        AND points_earned > 0

),

thresholds AS (
    SELECT
        3.0     AS pts_per_dollar_multiplier,   -- Flag if member earns 3x peer avg pts per dollar
        10      AS min_accrual_events,          -- Minimum events to establish pattern
        5000    AS min_points_farmed,           -- Minimum excess points to surface finding
        180     AS lookback_days
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Member-level accrual statistics
member_accrual_stats AS (
    SELECT
        member_id,
        COUNT(*)                                        AS accrual_event_count,
        SUM(points_earned)                              AS total_points_earned,
        SUM(transaction_amount)                         AS total_spend,
        ROUND(SUM(points_earned) / NULLIF(SUM(transaction_amount), 0), 4)
                                                        AS points_per_dollar,
        -- Bonus accrual share: what % of points came from non-purchase sources
        ROUND(100.0 * SUM(CASE WHEN accrual_reason != 'purchase'
                               THEN points_earned ELSE 0 END)
            / NULLIF(SUM(points_earned), 0), 1)         AS bonus_accrual_pct,
        -- Most exploited category
        MODE(accrual_category)                          AS top_accrual_category,
        MIN(accrual_timestamp)                          AS first_accrual,
        MAX(accrual_timestamp)                          AS last_accrual
    FROM normalized_accruals
    GROUP BY 1
),

-- Population benchmark: average points per dollar across all members
population_benchmark AS (
    SELECT
        AVG(points_per_dollar)                          AS avg_pts_per_dollar,
        PERCENTILE_CONT(0.90) WITHIN GROUP
            (ORDER BY points_per_dollar)                AS p90_pts_per_dollar,
        STDDEV(points_per_dollar)                       AS stddev_pts_per_dollar
    FROM member_accrual_stats
    WHERE accrual_event_count >= 10     -- only established members in benchmark
),

-- Flag members whose earn rate exceeds the population multiple
flagged_members AS (
    SELECT
        m.*,
        b.avg_pts_per_dollar,
        b.p90_pts_per_dollar,
        ROUND(m.points_per_dollar / NULLIF(b.avg_pts_per_dollar, 0), 2)
                                                        AS multiple_vs_avg,
        -- Estimated excess points: what they earned above expected rate
        ROUND(m.total_points_earned
            - (m.total_spend * b.avg_pts_per_dollar), 0) AS excess_points_earned,
        t.pts_per_dollar_multiplier,
        CASE
            WHEN m.points_per_dollar >= t.pts_per_dollar_multiplier * b.avg_pts_per_dollar
             AND m.bonus_accrual_pct >= 40              THEN 'HIGH — Rate + Bonus Exploitation'
            WHEN m.points_per_dollar >= t.pts_per_dollar_multiplier * b.avg_pts_per_dollar
                                                        THEN 'MEDIUM — Abnormal Earn Rate'
            WHEN m.bonus_accrual_pct >= 60              THEN 'MEDIUM — Bonus Concentration'
            ELSE 'LOW'
        END                                             AS signal_confidence
    FROM member_accrual_stats m
    CROSS JOIN population_benchmark b
    CROSS JOIN thresholds t
    WHERE
        m.accrual_event_count >= t.min_accrual_events
        AND (
            m.points_per_dollar >= t.pts_per_dollar_multiplier * b.avg_pts_per_dollar
            OR m.bonus_accrual_pct >= 60
        )
        AND (m.total_points_earned
             - (m.total_spend * b.avg_pts_per_dollar)) >= t.min_points_farmed
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    member_id,
    accrual_event_count,
    total_points_earned,
    total_spend,
    points_per_dollar                                   AS member_pts_per_dollar,
    avg_pts_per_dollar                                  AS population_avg_pts_per_dollar,
    multiple_vs_avg                                     AS earn_rate_vs_population,
    excess_points_earned,
    bonus_accrual_pct,
    top_accrual_category,
    first_accrual,
    last_accrual,

    signal_confidence,
    'Point Farming'                                     AS signal_name,
    'Member ' || member_id
        || ' earned ' || points_per_dollar::VARCHAR
        || ' points per dollar vs population average of '
        || ROUND(avg_pts_per_dollar, 2)::VARCHAR
        || ' (' || multiple_vs_avg::VARCHAR || 'x). '
        || 'Estimated excess points above expected rate: '
        || ROUND(excess_points_earned, 0)::VARCHAR
        || '. Bonus accrual share: ' || bonus_accrual_pct::VARCHAR
        || '%. Top category: ' || COALESCE(top_accrual_category, 'unspecified')
                                                        AS glass_box_verdict

FROM flagged_members
ORDER BY signal_confidence, excess_points_earned DESC;

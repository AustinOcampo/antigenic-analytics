-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: PLAN STACKING
-- =============================================================================
-- File:     plan_stacking_detection.sql
-- Signal:   S09 of 10 — Subscription & Recurring Billing Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Coordinated signups that share behavioral fingerprints but use different
-- identities to stack family or team plans. Exploiters create multiple
-- "family members" or "team members" who are actually the same person or
-- a small group, splitting one expensive subscription into multiple cheaper
-- ones or exploiting per-seat pricing by sharing access beyond the licensed
-- scope.
--
-- BEHAVIORAL TELL:
-- Legitimate family or team plans show diverse usage patterns — different
-- content preferences, different active hours, different devices. Stacked
-- plans show convergence: the "family members" all use the same devices,
-- log in from the same IPs, have the same usage patterns, and were all
-- created within a short window. The plan is team-sized but the behavior
-- is single-user.
--
-- DATA REQUIREMENTS:
-- Requires: account_id, plan_id, plan_type, member_id, member_created_at,
--           member_device_id, member_ip_address
-- Optional: member_email_domain, member_usage_hours, member_content_preferences,
--           plan_owner_id, member_login_times
--
-- TUNING PARAMETERS:
-- * min_plan_members         — minimum members on a plan to analyze (default: 3)
-- * device_overlap_threshold — % of members sharing devices to flag (default: 50%)
-- * ip_overlap_threshold     — % of members sharing IPs to flag (default: 60%)
-- * creation_window_hours    — hours between member adds to flag as burst (default: 24)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $5K–$50K in plan arbitrage
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_plans AS (

    SELECT
        plan_id                 AS plan_id,                  -- expected: VARCHAR / STRING
        plan_type               AS plan_type,                -- expected: VARCHAR ('family','team','business')
        owner_account_id        AS plan_owner_id,            -- expected: VARCHAR / STRING
        monthly_price           AS plan_monthly_price,       -- expected: FLOAT / NUMBER
        max_members             AS plan_max_members,         -- expected: INTEGER

    FROM your_plan_table                                     -- << REPLACE WITH YOUR TABLE

),

normalized_members AS (

    SELECT
        member_id               AS member_id,                -- expected: VARCHAR / STRING
        plan_id                 AS plan_id,                  -- expected: VARCHAR / STRING
        account_id              AS member_account_id,        -- expected: VARCHAR / STRING
        added_at                AS member_created_at,        -- expected: TIMESTAMP_NTZ
        device_id               AS member_device_id,         -- expected: VARCHAR
        ip_address              AS member_ip_address,        -- expected: VARCHAR
        email_domain            AS member_email_domain,      -- expected: VARCHAR

    FROM your_member_table                                   -- << REPLACE WITH YOUR TABLE

),

normalized_usage AS (

    SELECT
        member_id               AS member_id,                -- expected: VARCHAR / STRING
        activity_date           AS activity_date,            -- expected: DATE
        active_hour             AS active_hour,              -- expected: INTEGER (0-23)
        session_device_id       AS session_device_id,        -- expected: VARCHAR

    FROM your_usage_table                                    -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        3       AS min_plan_members,            -- need at least 3 members to analyze stacking
        50.0    AS device_overlap_threshold,    -- 50%+ members sharing a device = same person
        60.0    AS ip_overlap_threshold,        -- 60%+ members on same IP = same location always
        24      AS creation_window_hours,       -- all members added within 24 hrs = batch creation
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

-- Step 1: Plan-level member analysis
plan_member_stats AS (
    SELECT
        p.plan_id,
        p.plan_type,
        p.plan_owner_id,
        p.plan_monthly_price,
        COUNT(DISTINCT m.member_id)                         AS member_count,
        COUNT(DISTINCT m.member_device_id)                  AS distinct_devices,
        COUNT(DISTINCT m.member_ip_address)                 AS distinct_ips,
        COUNT(DISTINCT m.member_email_domain)               AS distinct_email_domains,
        MIN(m.member_created_at)                            AS first_member_added,
        MAX(m.member_created_at)                            AS last_member_added,
        DATEDIFF('hour', MIN(m.member_created_at),
                 MAX(m.member_created_at))                  AS member_add_span_hours,
        -- Device overlap: how many members share the same device
        ROUND(100.0 * (COUNT(DISTINCT m.member_id) - COUNT(DISTINCT m.member_device_id))
            / NULLIF(COUNT(DISTINCT m.member_id) - 1, 0), 1)
                                                            AS device_overlap_pct,
        -- IP overlap
        ROUND(100.0 * (COUNT(DISTINCT m.member_id) - COUNT(DISTINCT m.member_ip_address))
            / NULLIF(COUNT(DISTINCT m.member_id) - 1, 0), 1)
                                                            AS ip_overlap_pct
    FROM normalized_plans p
    INNER JOIN normalized_members m
        ON p.plan_id = m.plan_id
        AND m.member_created_at >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
    GROUP BY p.plan_id, p.plan_type, p.plan_owner_id, p.plan_monthly_price
),

-- Step 2: Usage pattern convergence across members
usage_convergence AS (
    SELECT
        m.plan_id,
        -- Device sharing during actual usage (not just registration)
        COUNT(DISTINCT u.session_device_id)                 AS usage_distinct_devices,
        COUNT(DISTINCT m.member_id)                         AS usage_members,
        ROUND(100.0 * COUNT(DISTINCT u.session_device_id)
            / NULLIF(COUNT(DISTINCT m.member_id), 0), 1)    AS device_to_member_ratio_pct,
        -- Active hour overlap: do all members use at the same times?
        COUNT(DISTINCT u.active_hour)                       AS distinct_active_hours,
        STDDEV(u.active_hour)                               AS active_hour_stddev
    FROM normalized_members m
    INNER JOIN normalized_usage u
        ON m.member_id = u.member_id
        AND u.activity_date >= DATEADD('day', -30, CURRENT_TIMESTAMP())
    GROUP BY m.plan_id
),

-- Step 3: Score and flag
flagged_plans AS (
    SELECT
        pms.*,
        uc.device_to_member_ratio_pct                       AS usage_device_ratio_pct,
        uc.distinct_active_hours,
        uc.active_hour_stddev,
        CASE
            WHEN pms.distinct_devices = 1
             AND pms.member_count >= 3                       THEN 'HIGH — All Members on Single Device'
            WHEN pms.device_overlap_pct >= 70
             AND pms.member_add_span_hours <= (SELECT creation_window_hours FROM thresholds)
             AND pms.ip_overlap_pct >= 80                    THEN 'HIGH — Burst Creation + Shared Infrastructure'
            WHEN pms.device_overlap_pct >= (SELECT device_overlap_threshold FROM thresholds)
             AND pms.ip_overlap_pct >= (SELECT ip_overlap_threshold FROM thresholds)
                                                            THEN 'MEDIUM — Device + IP Overlap'
            WHEN pms.member_add_span_hours <= 1
             AND pms.member_count >= 4
             AND pms.distinct_email_domains <= 1             THEN 'MEDIUM — Instant Batch Creation'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM plan_member_stats pms
    LEFT JOIN usage_convergence uc
        ON pms.plan_id = uc.plan_id
    CROSS JOIN thresholds t
    WHERE pms.member_count >= t.min_plan_members
      AND (
          pms.device_overlap_pct >= t.device_overlap_threshold
          OR pms.ip_overlap_pct >= t.ip_overlap_threshold
          OR pms.member_add_span_hours <= t.creation_window_hours
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    plan_id,
    plan_type,
    plan_owner_id,
    plan_monthly_price,
    member_count,
    distinct_devices,
    distinct_ips,
    device_overlap_pct,
    ip_overlap_pct,
    member_add_span_hours,
    distinct_email_domains,
    usage_device_ratio_pct,

    signal_confidence,
    'Plan Stacking'                                         AS signal_name,
    'Plan ' || plan_id || ' (' || plan_type || '): '
        || member_count::VARCHAR || ' members but only '
        || distinct_devices::VARCHAR || ' devices and '
        || distinct_ips::VARCHAR || ' IPs. '
        || 'Device overlap: ' || COALESCE(device_overlap_pct::VARCHAR, 'N/A') || '%. '
        || 'IP overlap: ' || COALESCE(ip_overlap_pct::VARCHAR, 'N/A') || '%. '
        || 'Members added within ' || member_add_span_hours::VARCHAR || ' hours. '
        || distinct_email_domains::VARCHAR
        || ' email domains.'                                AS glass_box_verdict

FROM flagged_plans
ORDER BY signal_confidence, member_count DESC;

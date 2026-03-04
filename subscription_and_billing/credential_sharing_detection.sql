-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: CREDENTIAL SHARING DETECTION
-- =============================================================================
-- File:     credential_sharing_detection.sql
-- Signal:   S03 of 10 — Subscription & Recurring Billing Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Credential sharing patterns where a single account is accessed from dozens
-- of locations simultaneously, far exceeding the usage profile of a single
-- subscriber. This signal separates legitimate multi-device usage (a person
-- on their phone, laptop, and TV) from commercial-scale credential sharing
-- (one account accessed from 40 cities in a single day).
--
-- BEHAVIORAL TELL:
-- Legitimate users have a small, stable set of devices and locations — home,
-- office, mobile. Shared credentials produce geographically impossible
-- patterns: simultaneous sessions from different cities, dozens of unique
-- IPs per day, and device counts that grow linearly over time rather than
-- stabilizing. The concurrent session count is the strongest single indicator.
--
-- DATA REQUIREMENTS:
-- Requires: account_id, session_id, session_start, session_ip_address,
--           session_device_id
-- Optional: session_city, session_country, session_duration_minutes,
--           subscription_plan, max_allowed_devices
--
-- TUNING PARAMETERS:
-- * max_daily_unique_ips     — unique IPs per day above which to flag (default: 10)
-- * max_concurrent_sessions  — simultaneous sessions to flag (default: 5)
-- * max_daily_unique_cities  — unique cities per day to flag (default: 5)
-- * min_flagged_days         — days exceeding thresholds to flag (default: 5)
-- * lookback_days            — analysis window (default: 30)
--
-- TYPICAL EXPOSURE: $5K–$100K in revenue leakage per account
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_sessions AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        session_id              AS session_id,               -- expected: VARCHAR / STRING
        session_start           AS session_start,            -- expected: TIMESTAMP_NTZ
        session_end             AS session_end,              -- expected: TIMESTAMP_NTZ (NULL if still active)
        ip_address              AS session_ip_address,       -- expected: VARCHAR
        device_id               AS session_device_id,        -- expected: VARCHAR
        city                    AS session_city,             -- expected: VARCHAR (NULL if not geolocated)
        country                 AS session_country,          -- expected: VARCHAR
        duration_minutes        AS session_duration_minutes, -- expected: FLOAT

    FROM your_session_table                                  -- << REPLACE WITH YOUR TABLE

),

normalized_accounts AS (

    SELECT
        account_id              AS account_id,               -- expected: VARCHAR / STRING
        plan_name               AS subscription_plan,        -- expected: VARCHAR
        max_devices             AS max_allowed_devices,      -- expected: INTEGER (NULL if unlimited)

    FROM your_account_table                                  -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        10      AS max_daily_unique_ips,        -- 10+ unique IPs in a day = not one person
        5       AS max_concurrent_sessions,     -- 5+ simultaneous sessions = sharing
        5       AS max_daily_unique_cities,     -- 5+ cities in one day = geographically impossible
        5       AS min_flagged_days,            -- must exceed thresholds on 5+ days to filter noise
        30      AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

sessions_in_scope AS (
    SELECT *
    FROM normalized_sessions
    WHERE session_start >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 1: Daily uniqueness metrics per account
daily_metrics AS (
    SELECT
        account_id,
        DATE(session_start)                                 AS activity_date,
        COUNT(DISTINCT session_ip_address)                  AS unique_ips,
        COUNT(DISTINCT session_device_id)                   AS unique_devices,
        COUNT(DISTINCT session_city)                        AS unique_cities,
        COUNT(DISTINCT session_id)                          AS total_sessions,
        SUM(session_duration_minutes)                       AS total_session_minutes
    FROM sessions_in_scope
    GROUP BY account_id, DATE(session_start)
),

-- Step 2: Concurrent session detection
-- Find overlapping sessions for the same account
concurrent_sessions AS (
    SELECT
        a.account_id,
        a.session_id                                        AS session_a,
        b.session_id                                        AS session_b,
        a.session_start,
        a.session_ip_address                                AS ip_a,
        b.session_ip_address                                AS ip_b
    FROM sessions_in_scope a
    INNER JOIN sessions_in_scope b
        ON a.account_id = b.account_id
        AND a.session_id < b.session_id
        AND a.session_start <= COALESCE(b.session_end, CURRENT_TIMESTAMP())
        AND b.session_start <= COALESCE(a.session_end, CURRENT_TIMESTAMP())
        AND a.session_ip_address != b.session_ip_address    -- different locations
),

max_concurrent AS (
    SELECT
        account_id,
        DATE(session_start)                                 AS activity_date,
        COUNT(*) + 1                                        AS concurrent_session_count
    FROM concurrent_sessions
    GROUP BY account_id, DATE(session_start)
),

-- Step 3: Aggregate account-level patterns
account_sharing_stats AS (
    SELECT
        dm.account_id,
        COUNT(DISTINCT dm.activity_date)                    AS active_days,
        -- IP analysis
        AVG(dm.unique_ips)                                  AS avg_daily_unique_ips,
        MAX(dm.unique_ips)                                  AS max_daily_unique_ips,
        COUNT(CASE WHEN dm.unique_ips >= (SELECT max_daily_unique_ips FROM thresholds)
              THEN 1 END)                                   AS days_exceeding_ip_threshold,
        -- Device analysis
        COUNT(DISTINCT s.session_device_id)                 AS total_unique_devices,
        AVG(dm.unique_devices)                              AS avg_daily_unique_devices,
        -- City analysis
        COUNT(DISTINCT s.session_city)                      AS total_unique_cities,
        AVG(dm.unique_cities)                               AS avg_daily_unique_cities,
        COUNT(CASE WHEN dm.unique_cities >= (SELECT max_daily_unique_cities FROM thresholds)
              THEN 1 END)                                   AS days_exceeding_city_threshold,
        -- Concurrency
        COALESCE(MAX(mc.concurrent_session_count), 1)       AS max_concurrent_sessions,
        COUNT(CASE WHEN mc.concurrent_session_count >= (SELECT max_concurrent_sessions FROM thresholds)
              THEN 1 END)                                   AS days_exceeding_concurrent_threshold,
        -- Volume
        SUM(dm.total_sessions)                              AS total_sessions,
        SUM(dm.total_session_minutes)                       AS total_session_minutes
    FROM daily_metrics dm
    INNER JOIN sessions_in_scope s
        ON dm.account_id = s.account_id AND dm.activity_date = DATE(s.session_start)
    LEFT JOIN max_concurrent mc
        ON dm.account_id = mc.account_id AND dm.activity_date = mc.activity_date
    GROUP BY dm.account_id
),

-- Step 4: Score and flag
flagged_accounts AS (
    SELECT
        ass.*,
        na.subscription_plan,
        na.max_allowed_devices,
        CASE
            WHEN ass.max_concurrent_sessions >= 10
             AND ass.days_exceeding_ip_threshold >= 10
             AND ass.total_unique_cities >= 15               THEN 'HIGH — Commercial-Scale Sharing'
            WHEN ass.days_exceeding_concurrent_threshold >= (SELECT min_flagged_days FROM thresholds)
             AND ass.days_exceeding_ip_threshold >= (SELECT min_flagged_days FROM thresholds)
                                                            THEN 'HIGH — Persistent Concurrent + Multi-IP'
            WHEN ass.total_unique_devices > COALESCE(na.max_allowed_devices, 999) * 3
             AND ass.days_exceeding_ip_threshold >= 3        THEN 'MEDIUM — Exceeds Device Limit + Multi-IP'
            WHEN ass.days_exceeding_city_threshold >= (SELECT min_flagged_days FROM thresholds)
                                                            THEN 'MEDIUM — Geographically Impossible Pattern'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM account_sharing_stats ass
    LEFT JOIN normalized_accounts na
        ON ass.account_id = na.account_id
    CROSS JOIN thresholds t
    WHERE ass.days_exceeding_ip_threshold >= t.min_flagged_days
       OR ass.days_exceeding_concurrent_threshold >= t.min_flagged_days
       OR ass.days_exceeding_city_threshold >= t.min_flagged_days
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    account_id,
    subscription_plan,
    active_days,
    avg_daily_unique_ips,
    max_daily_unique_ips,
    total_unique_devices,
    max_allowed_devices,
    total_unique_cities,
    max_concurrent_sessions,
    days_exceeding_ip_threshold,
    days_exceeding_concurrent_threshold,
    total_sessions,

    signal_confidence,
    'Credential Sharing Detection'                          AS signal_name,
    'Account ' || account_id
        || ' (' || COALESCE(subscription_plan, 'unknown plan') || '): '
        || 'Avg ' || ROUND(avg_daily_unique_ips, 1)::VARCHAR
        || ' unique IPs/day (max ' || max_daily_unique_ips::VARCHAR || '). '
        || total_unique_devices::VARCHAR || ' total devices'
        || CASE WHEN max_allowed_devices IS NOT NULL
           THEN ' (limit: ' || max_allowed_devices::VARCHAR || ')'
           ELSE '' END || '. '
        || total_unique_cities::VARCHAR || ' unique cities. '
        || 'Max ' || max_concurrent_sessions::VARCHAR || ' concurrent sessions. '
        || days_exceeding_ip_threshold::VARCHAR
        || ' days exceeded IP threshold.'                   AS glass_box_verdict

FROM flagged_accounts
ORDER BY signal_confidence, max_concurrent_sessions DESC;

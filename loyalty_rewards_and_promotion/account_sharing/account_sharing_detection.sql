-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: ACCOUNT SHARING / POOLING
-- =============================================================================
-- File:     account_sharing_detection.sql
-- Signal:   L04 of 10 — Loyalty & Rewards
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Single loyalty accounts accessed from multiple devices or locations
-- simultaneously or in rapid succession, indicating credential sharing
-- across a fraud ring. Pooled accounts are used to concentrate points
-- from multiple people into one account for high-value redemptions that
-- individual accounts couldn't reach on their own.
--
-- BEHAVIORAL TELL:
-- A legitimate member accesses their account from a small, consistent
-- set of devices — phone, laptop, maybe a tablet. A shared account
-- shows access from many devices, multiple geographic locations,
-- and in some cases near-simultaneous sessions that are physically
-- impossible for one person. The device and location footprint
-- is far larger than any single customer would produce.
--
-- DATA REQUIREMENTS:
-- Requires: member_id, session_timestamp, ip_address OR device_fingerprint
-- Improves with: geo_location, user_agent, login_timestamp
--
-- TUNING PARAMETERS:
-- * max_devices_legitimate    — devices before flagging sharing (default: 4)
-- * impossible_travel_hours   — hours between sessions in different geos (default: 2)
-- * min_sessions_to_analyze   — minimum sessions for pattern (default: 10)
-- * velocity_window_days      — window for device/location analysis (default: 90)
--
-- TYPICAL EXPOSURE: $10,000 — $100,000
-- =============================================================================

WITH normalized_sessions AS (

    SELECT
        member_id               AS member_id,               -- expected: VARCHAR
        session_timestamp       AS session_timestamp,       -- expected: TIMESTAMP_NTZ
        ip_address              AS ip_address,              -- expected: VARCHAR
        device_fingerprint      AS device_fingerprint,      -- expected: VARCHAR (NULL ok)
        geo_country             AS geo_country,             -- expected: VARCHAR (NULL ok)
        geo_city                AS geo_city                 -- expected: VARCHAR (NULL ok)

    FROM your_session_table         -- << CHANGE THIS (login / session events table)

    WHERE session_timestamp >= DATEADD('day', -90, CURRENT_DATE)

),

thresholds AS (
    SELECT
        4       AS max_devices_legitimate,      -- More than 4 devices = sharing flag
        2       AS impossible_travel_hours,     -- Sessions from different countries < 2hrs apart
        10      AS min_sessions_to_analyze
),

-- Member-level device and location footprint
member_footprint AS (
    SELECT
        member_id,
        COUNT(DISTINCT session_timestamp)               AS total_sessions,
        COUNT(DISTINCT device_fingerprint)              AS distinct_devices,
        COUNT(DISTINCT ip_address)                      AS distinct_ips,
        COUNT(DISTINCT geo_country)                     AS distinct_countries,
        COUNT(DISTINCT geo_city)                        AS distinct_cities,
        MIN(session_timestamp)                          AS first_session,
        MAX(session_timestamp)                          AS last_session
    FROM normalized_sessions
    GROUP BY 1
),

-- Impossible travel detection: same account, different country, short time gap
session_pairs AS (
    SELECT
        a.member_id,
        a.session_timestamp                             AS session_a_time,
        a.geo_country                                   AS country_a,
        b.session_timestamp                             AS session_b_time,
        b.geo_country                                   AS country_b,
        DATEDIFF('hour', a.session_timestamp, b.session_timestamp)
                                                        AS hours_between_sessions
    FROM normalized_sessions a
    JOIN normalized_sessions b
        ON  a.member_id = b.member_id
        AND a.session_timestamp < b.session_timestamp
        AND a.geo_country != b.geo_country
        AND a.geo_country IS NOT NULL
        AND b.geo_country IS NOT NULL
),

impossible_travel AS (
    SELECT
        member_id,
        COUNT(*)                                        AS impossible_travel_count,
        MIN(hours_between_sessions)                     AS shortest_impossible_gap_hours,
        LISTAGG(country_a || '→' || country_b || ' (' || hours_between_sessions::VARCHAR || 'h)', ' | ')
            WITHIN GROUP (ORDER BY session_a_time)      AS travel_detail
    FROM session_pairs
    CROSS JOIN thresholds t
    WHERE hours_between_sessions <= t.impossible_travel_hours
    GROUP BY 1
),

-- Combine footprint and impossible travel
combined AS (
    SELECT
        f.*,
        COALESCE(it.impossible_travel_count, 0)         AS impossible_travel_events,
        it.shortest_impossible_gap_hours,
        it.travel_detail,
        t.max_devices_legitimate,
        t.min_sessions_to_analyze
    FROM member_footprint f
    LEFT JOIN impossible_travel it ON f.member_id = it.member_id
    CROSS JOIN thresholds t
    WHERE f.total_sessions >= t.min_sessions_to_analyze
)

SELECT
    member_id,
    total_sessions,
    distinct_devices,
    distinct_ips,
    distinct_countries,
    distinct_cities,
    impossible_travel_events,
    shortest_impossible_gap_hours,
    travel_detail,
    first_session,
    last_session,

    CASE
        WHEN impossible_travel_events >= 2              THEN 'HIGH — Impossible Travel Pattern'
        WHEN impossible_travel_events >= 1
         AND distinct_devices >= max_devices_legitimate THEN 'HIGH — Travel + Device Anomaly'
        WHEN distinct_devices >= max_devices_legitimate * 2
                                                        THEN 'MEDIUM — Excessive Device Count'
        WHEN distinct_countries >= 3                    THEN 'MEDIUM — Multi-Country Access'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'Account Sharing / Pooling'                         AS signal_name,
    'Member ' || member_id
        || ' accessed from ' || distinct_devices::VARCHAR
        || ' distinct devices, ' || distinct_ips::VARCHAR
        || ' IPs, and ' || distinct_countries::VARCHAR
        || ' countries over 90 days. '
        || COALESCE(
            impossible_travel_events::VARCHAR
            || ' impossible travel events detected (fastest: '
            || shortest_impossible_gap_hours::VARCHAR || ' hours between countries).',
            'No impossible travel detected.'
        )                                               AS glass_box_verdict

FROM combined
WHERE
    distinct_devices >= max_devices_legitimate
    OR impossible_travel_events >= 1

ORDER BY signal_confidence, distinct_devices DESC;

-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: VELOCITY AT ORIGINATION
-- =============================================================================
-- File:     velocity_at_origination_detection.sql
-- Signal:   I02 of 05 — Identity & Origination
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Burst application patterns where a single device, IP address, or shared
-- identity component appears across multiple distinct applications within
-- a rolling time window. Fraudsters operating identity rings don't submit
-- one application — they submit dozens in rapid succession, often testing
-- which synthetic identities pass before scaling up the ones that do.
-- Your application layer is the earliest possible detection point.
--
-- BEHAVIORAL TELL:
-- A legitimate applicant submits one application, maybe two if they shop
-- lenders. A fraud ring operating synthetic identities submits 15 applications
-- from the same IP across 3 hours, each with different names and SSNs but
-- the same device fingerprint. The device doesn't lie even when the identity does.
--
-- DATA REQUIREMENTS:
-- Requires: application_id, application_timestamp, ip_address
-- Improves with: device_fingerprint, ssn_hash, email_domain,
--               phone_number_hash, stated_address
--
-- TUNING PARAMETERS:
-- * velocity_window_hours    — burst detection window (default: 24 hours)
-- * min_applications         — applications per identifier to flag (default: 3)
-- * min_distinct_identities  — distinct SSNs/names in burst (default: 2)
--
-- TYPICAL EXPOSURE: $10,000 — $500,000 per ring
-- =============================================================================

WITH normalized_applications AS (

    SELECT
        application_id          AS application_id,          -- expected: VARCHAR
        applicant_id            AS applicant_id,            -- expected: VARCHAR
        ssn_hash                AS ssn_hash,                -- expected: VARCHAR (hashed)
        application_timestamp   AS application_timestamp,   -- expected: TIMESTAMP_NTZ
        ip_address              AS ip_address,              -- expected: VARCHAR
        device_fingerprint      AS device_fingerprint,      -- expected: VARCHAR (NULL ok)
        LOWER(SPLIT_PART(email, '@', 2))
                                AS email_domain,            -- expected: VARCHAR
        stated_annual_income    AS stated_annual_income,    -- expected: FLOAT
        application_status      AS application_status       -- expected: VARCHAR ('approved','declined','pending')

    FROM your_applications_table    -- << CHANGE THIS

    WHERE application_timestamp >= DATEADD('day', -90, CURRENT_DATE)

),

thresholds AS (
    SELECT
        24      AS velocity_window_hours,
        3       AS min_applications,
        2       AS min_distinct_identities
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- IP-level burst detection
ip_velocity AS (
    SELECT
        a.ip_address,
        DATE_TRUNC('day', a.application_timestamp)          AS application_day,
        COUNT(DISTINCT a.application_id)                    AS application_count,
        COUNT(DISTINCT a.applicant_id)                      AS distinct_applicants,
        COUNT(DISTINCT a.ssn_hash)                          AS distinct_ssns,
        COUNT(DISTINCT a.device_fingerprint)                AS distinct_devices,
        COUNT(DISTINCT a.email_domain)                      AS distinct_email_domains,
        SUM(CASE WHEN a.application_status = 'approved'
                 THEN 1 ELSE 0 END)                         AS approvals,
        MIN(a.application_timestamp)                        AS first_application,
        MAX(a.application_timestamp)                        AS last_application,
        DATEDIFF('hour',
            MIN(a.application_timestamp),
            MAX(a.application_timestamp))                   AS burst_hours,
        LISTAGG(DISTINCT a.applicant_id, ', ')
            WITHIN GROUP (ORDER BY a.application_timestamp) AS applicant_ids
    FROM normalized_applications a
    GROUP BY 1, 2
),

-- Device-level burst detection
device_velocity AS (
    SELECT
        a.device_fingerprint,
        DATE_TRUNC('day', a.application_timestamp)          AS application_day,
        COUNT(DISTINCT a.application_id)                    AS application_count,
        COUNT(DISTINCT a.applicant_id)                      AS distinct_applicants,
        COUNT(DISTINCT a.ssn_hash)                          AS distinct_ssns,
        COUNT(DISTINCT a.ip_address)                        AS distinct_ips,
        SUM(CASE WHEN a.application_status = 'approved'
                 THEN 1 ELSE 0 END)                         AS approvals,
        MIN(a.application_timestamp)                        AS first_application,
        MAX(a.application_timestamp)                        AS last_application,
        DATEDIFF('hour',
            MIN(a.application_timestamp),
            MAX(a.application_timestamp))                   AS burst_hours
    FROM normalized_applications a
    WHERE a.device_fingerprint IS NOT NULL
    GROUP BY 1, 2
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

-- IP-based velocity flags
SELECT
    ip_address                                          AS identifier_value,
    'ip_address'                                        AS identifier_type,
    application_day,
    application_count,
    distinct_applicants,
    distinct_ssns,
    distinct_devices,
    NULL::INTEGER                                       AS distinct_ips,
    approvals,
    burst_hours,
    first_application,
    last_application,
    applicant_ids,

    CASE
        WHEN application_count >= 10
         AND distinct_ssns >= 5                         THEN 'HIGH — Identity Ring Detected'
        WHEN application_count >= t.min_applications
         AND distinct_ssns >= t.min_distinct_identities THEN 'HIGH — Multi-Identity Burst'
        WHEN application_count >= t.min_applications    THEN 'MEDIUM — Velocity Flag'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'Velocity at Origination'                           AS signal_name,
    'IP ' || ip_address
        || ' submitted ' || application_count::VARCHAR
        || ' applications from ' || distinct_applicants::VARCHAR
        || ' distinct applicants using ' || distinct_ssns::VARCHAR
        || ' distinct SSNs in ' || burst_hours::VARCHAR
        || ' hours. ' || approvals::VARCHAR || ' approved.'
                                                        AS glass_box_verdict

FROM ip_velocity
CROSS JOIN thresholds t
WHERE application_count >= t.min_applications
  AND distinct_applicants >= t.min_distinct_identities

UNION ALL

-- Device-based velocity flags
SELECT
    device_fingerprint,
    'device_fingerprint',
    application_day,
    application_count,
    distinct_applicants,
    distinct_ssns,
    NULL,
    distinct_ips,
    approvals,
    burst_hours,
    first_application,
    last_application,
    NULL,

    CASE
        WHEN application_count >= 10
         AND distinct_ssns >= 5                         THEN 'HIGH — Identity Ring Detected'
        WHEN application_count >= t.min_applications
         AND distinct_ssns >= t.min_distinct_identities THEN 'HIGH — Multi-Identity Burst'
        WHEN application_count >= t.min_applications    THEN 'MEDIUM — Velocity Flag'
        ELSE 'LOW'
    END,

    'Velocity at Origination',
    'Device ' || device_fingerprint
        || ' submitted ' || application_count::VARCHAR
        || ' applications from ' || distinct_applicants::VARCHAR
        || ' distinct applicants using ' || distinct_ssns::VARCHAR
        || ' distinct SSNs. ' || approvals::VARCHAR || ' approved.'

FROM device_velocity
CROSS JOIN thresholds t
WHERE application_count >= t.min_applications
  AND distinct_applicants >= t.min_distinct_identities

ORDER BY signal_confidence, application_count DESC;

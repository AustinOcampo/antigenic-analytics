-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: KYC BYPASS INDICATORS
-- =============================================================================
-- File:     kyc_bypass_indicators_detection.sql
-- Signal:   I03 of 05 — Identity & Origination
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Applications that passed automated KYC verification but show behavioral
-- anomalies in the verification event itself — patterns inconsistent with
-- a legitimate person verifying their own identity. The KYC process
-- produces behavioral data (attempt counts, timing, document resubmission)
-- that contains fraud signals most risk teams never analyze.
--
-- BEHAVIORAL TELL:
-- A legitimate person verifying their identity submits their document once,
-- or maybe twice if the photo quality was poor. They complete the process
-- in a reasonable time window. They don't submit the same document with
-- minor alterations across multiple attempts. Fraudsters probing your KYC
-- system iterate — testing which document variants pass, at what time of
-- day your manual review queue is shortest, with what image manipulation
-- passes liveness detection. That iteration pattern is detectable.
--
-- DATA REQUIREMENTS:
-- Requires: application_id, kyc_attempt_count, kyc_result,
--           kyc_start_timestamp, kyc_complete_timestamp,
--           document_type, kyc_failure_reasons
-- Improves with: liveness_score, document_authenticity_score,
--               time_of_day, manual_review_flag
--
-- TUNING PARAMETERS:
-- * max_legitimate_attempts  — attempts above which = probing (default: 3)
-- * suspicious_hour_start    — off-hours start for manual review avoidance (default: 23)
-- * suspicious_hour_end      — off-hours end (default: 5)
-- * min_session_seconds      — completion too fast for legitimate human (default: 30)
-- * max_session_seconds      — completion too slow = automated tooling (default: 1800)
--
-- TYPICAL EXPOSURE: $5,000 — $100,000 per bypassed account
-- =============================================================================

WITH normalized_kyc_events AS (

    SELECT
        application_id          AS application_id,          -- expected: VARCHAR
        applicant_id            AS applicant_id,            -- expected: VARCHAR
        kyc_attempt_count       AS kyc_attempt_count,       -- expected: INTEGER
        kyc_result              AS kyc_result,              -- expected: VARCHAR ('pass','fail','manual')
        kyc_start_timestamp     AS kyc_start_timestamp,     -- expected: TIMESTAMP_NTZ
        kyc_complete_timestamp  AS kyc_complete_timestamp,  -- expected: TIMESTAMP_NTZ
        document_type           AS document_type,           -- expected: VARCHAR ('passport','license','id')
        kyc_failure_reasons     AS kyc_failure_reasons,     -- expected: VARCHAR (NULL if passed first try)
        liveness_score          AS liveness_score,          -- expected: FLOAT 0-100 (NULL ok)
        document_auth_score     AS document_auth_score,     -- expected: FLOAT 0-100 (NULL ok)
        manual_review_flag      AS manual_review_flag,      -- expected: BOOLEAN / INTEGER
        ip_address              AS ip_address,
        device_fingerprint      AS device_fingerprint

    FROM your_kyc_events_table      -- << CHANGE THIS

    WHERE kyc_start_timestamp >= DATEADD('year', -1, CURRENT_DATE)
        AND kyc_result = 'pass'     -- Only analyze passed KYC events

),

thresholds AS (
    SELECT
        3       AS max_legitimate_attempts,     -- More than 3 attempts = probing
        23      AS suspicious_hour_start,       -- 11pm onwards = off-hours
        5       AS suspicious_hour_end,         -- Until 5am
        30      AS min_session_seconds,         -- Faster than 30s = bot
        1800    AS max_session_seconds,         -- Slower than 30min = automated tooling
        70.0    AS min_liveness_score,          -- Below 70 = liveness concern
        70.0    AS min_doc_auth_score           -- Below 70 = document concern
),

-- Score each KYC event
kyc_scored AS (
    SELECT
        application_id,
        applicant_id,
        kyc_attempt_count,
        kyc_result,
        kyc_start_timestamp,
        kyc_complete_timestamp,
        document_type,
        kyc_failure_reasons,
        liveness_score,
        document_auth_score,
        manual_review_flag,
        ip_address,
        DATEDIFF('second', kyc_start_timestamp, kyc_complete_timestamp)
                                                            AS session_duration_seconds,
        HOUR(kyc_start_timestamp)                           AS submission_hour,
        -- Individual bypass indicators
        CASE WHEN kyc_attempt_count > t.max_legitimate_attempts
             THEN 1 ELSE 0 END                              AS excessive_attempts_flag,
        CASE WHEN HOUR(kyc_start_timestamp) >= t.suspicious_hour_start
              OR HOUR(kyc_start_timestamp) < t.suspicious_hour_end
             THEN 1 ELSE 0 END                              AS off_hours_flag,
        CASE WHEN DATEDIFF('second', kyc_start_timestamp, kyc_complete_timestamp)
                  < t.min_session_seconds
             THEN 1 ELSE 0 END                              AS too_fast_flag,
        CASE WHEN DATEDIFF('second', kyc_start_timestamp, kyc_complete_timestamp)
                  > t.max_session_seconds
             THEN 1 ELSE 0 END                              AS too_slow_flag,
        CASE WHEN liveness_score IS NOT NULL
              AND liveness_score < t.min_liveness_score
             THEN 1 ELSE 0 END                              AS low_liveness_flag,
        CASE WHEN document_auth_score IS NOT NULL
              AND document_auth_score < t.min_doc_auth_score
             THEN 1 ELSE 0 END                              AS low_doc_auth_flag
    FROM normalized_kyc_events
    CROSS JOIN thresholds t
),

flagged AS (
    SELECT
        *,
        (excessive_attempts_flag + off_hours_flag + too_fast_flag
         + too_slow_flag + low_liveness_flag + low_doc_auth_flag)
                                                            AS bypass_indicator_count
    FROM kyc_scored
    WHERE
        excessive_attempts_flag = 1
        OR (too_fast_flag = 1 AND off_hours_flag = 1)
        OR low_liveness_flag = 1
        OR low_doc_auth_flag = 1
        OR (off_hours_flag = 1 AND kyc_attempt_count >= 2)
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    application_id,
    applicant_id,
    kyc_attempt_count,
    session_duration_seconds,
    submission_hour,
    document_type,
    liveness_score,
    document_auth_score,
    bypass_indicator_count,
    excessive_attempts_flag,
    off_hours_flag,
    too_fast_flag,
    low_liveness_flag,
    low_doc_auth_flag,
    ip_address,

    CASE
        WHEN bypass_indicator_count >= 3                    THEN 'HIGH — Multiple Bypass Indicators'
        WHEN excessive_attempts_flag = 1
         AND (low_liveness_flag = 1 OR low_doc_auth_flag = 1)
                                                            THEN 'HIGH — Probing + Score Anomaly'
        WHEN bypass_indicator_count = 2                     THEN 'MEDIUM — Dual Indicator'
        ELSE 'LOW'
    END                                                     AS signal_confidence,

    'KYC Bypass Indicators'                                 AS signal_name,
    'Application ' || application_id
        || ' passed KYC with ' || bypass_indicator_count::VARCHAR
        || ' anomaly indicators: '
        || CASE WHEN excessive_attempts_flag = 1
               THEN '[' || kyc_attempt_count::VARCHAR || ' attempts] ' ELSE '' END
        || CASE WHEN off_hours_flag = 1
               THEN '[Off-hours: ' || submission_hour::VARCHAR || ':00] ' ELSE '' END
        || CASE WHEN too_fast_flag = 1
               THEN '[Completed in ' || session_duration_seconds::VARCHAR || 's] ' ELSE '' END
        || CASE WHEN low_liveness_flag = 1
               THEN '[Liveness: ' || ROUND(liveness_score, 0)::VARCHAR || '] ' ELSE '' END
        || CASE WHEN low_doc_auth_flag = 1
               THEN '[Doc Auth: ' || ROUND(document_auth_score, 0)::VARCHAR || '] ' ELSE '' END
                                                            AS glass_box_verdict

FROM flagged
ORDER BY signal_confidence, bypass_indicator_count DESC;

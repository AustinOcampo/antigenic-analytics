-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: SYNTHETIC IDENTITY DETECTION
-- =============================================================================
-- File:     synthetic_identity_detection.sql
-- Signal:   I01 of 05 — Identity & Origination
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Applications where identity components don't cohere — SSN issued in a state
-- inconsistent with the applicant's history, age-to-SSN issuance mismatches,
-- identity elements that appear across multiple distinct applications, and
-- thin credit files with statistical anomalies. Synthetic identities are built
-- from real and fabricated components specifically to pass automated KYC checks.
-- They fail under behavioral scrutiny.
--
-- THE CONSTRUCTION METHOD:
-- A synthetic identity typically combines:
--   * A real SSN (often belonging to a child, elderly person, or recent immigrant
--     with no credit history) — provides a valid SSN that passes format checks
--   * A fabricated name — doesn't match the SSN owner
--   * A real but unassociated address — passes address verification
--   * A manufactured phone/email — passes contact verification
-- The result passes individual field validation but fails coherence analysis.
--
-- BEHAVIORAL TELL:
-- Legitimate identities have a coherent history. The SSN was issued when the
-- person was young, in the state where they grew up. Their address history
-- makes geographic sense. Their credit file thickness matches their age.
-- Synthetic identities have coherence gaps — the SSN issuance year doesn't
-- match the claimed birthdate, the address has never appeared on any prior
-- application, the credit file is thin but the claimed income is high.
--
-- DATA REQUIREMENTS:
-- Requires: application_id, applicant_id, ssn_last4 (or full SSN hashed),
--           date_of_birth, ssn_issue_state, application_state,
--           credit_file_age_months, application_timestamp
-- Improves with: prior_address_count, name_ssn_match_score (from KYC vendor),
--               phone_age_days, email_age_days, ip_address
--
-- TUNING PARAMETERS:
-- * ssn_age_mismatch_years   — SSN issued after DOB + N years = suspicious (default: 18)
-- * thin_file_threshold      — credit file months below which = thin (default: 24)
-- * identity_reuse_window    — days to check for SSN reuse across apps (default: 365)
-- * min_coherence_failures   — how many coherence checks must fail to flag (default: 2)
--
-- TYPICAL EXPOSURE: $5,000 — $50,000 per synthetic account
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_applications AS (

    SELECT
        application_id          AS application_id,          -- expected: VARCHAR
        applicant_id            AS applicant_id,            -- expected: VARCHAR
        -- Use hashed SSN or last4 — never store raw SSN in analytics layer
        ssn_hash                AS ssn_hash,                -- expected: VARCHAR (hashed)
        date_of_birth           AS date_of_birth,           -- expected: DATE
        ssn_issue_year          AS ssn_issue_year,          -- expected: INTEGER (NULL ok)
        ssn_issue_state         AS ssn_issue_state,         -- expected: VARCHAR (NULL ok)
        application_state       AS application_state,       -- expected: VARCHAR (state of application)
        credit_file_age_months  AS credit_file_age_months,  -- expected: INTEGER (from bureau)
        stated_annual_income    AS stated_annual_income,    -- expected: FLOAT
        application_timestamp   AS application_timestamp,   -- expected: TIMESTAMP_NTZ
        ip_address              AS ip_address,              -- expected: VARCHAR
        device_fingerprint      AS device_fingerprint,      -- expected: VARCHAR (NULL ok)
        -- KYC vendor scores (map to your vendor's output field names)
        name_ssn_match_score    AS name_ssn_match_score,    -- expected: FLOAT 0-100 (NULL ok)
        address_match_score     AS address_match_score,     -- expected: FLOAT 0-100 (NULL ok)
        phone_tenure_days       AS phone_tenure_days,       -- expected: INTEGER (NULL ok)
        email_tenure_days       AS email_tenure_days        -- expected: INTEGER (NULL ok)

    FROM your_applications_table    -- << CHANGE THIS

    WHERE application_timestamp >= DATEADD('year', -2, CURRENT_DATE)

),

thresholds AS (
    SELECT
        18      AS ssn_age_mismatch_years,      -- SSN issued more than 18 years after DOB = flag
        24      AS thin_file_threshold_months,  -- Credit file under 24 months = thin
        365     AS identity_reuse_window_days,  -- Window to detect SSN reuse across apps
        2       AS min_coherence_failures,      -- Minimum failed checks to flag
        50.0    AS min_name_ssn_score,          -- Below this score = name/SSN mismatch
        30      AS min_phone_tenure_days,       -- Phone registered < 30 days = burner risk
        30      AS min_email_tenure_days        -- Email created < 30 days = synthetic risk
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Coherence check 1: SSN issuance year vs date of birth
-- SSN should be issued within a few years of birth for most people
-- A 25-year-old with an SSN issued 3 years ago is suspicious
ssn_age_coherence AS (
    SELECT
        application_id,
        applicant_id,
        ssn_hash,
        date_of_birth,
        ssn_issue_year,
        DATEDIFF('year', date_of_birth, CURRENT_DATE)       AS applicant_age_years,
        CASE
            WHEN ssn_issue_year IS NOT NULL
             AND (YEAR(CURRENT_DATE) - ssn_issue_year)
                 < (DATEDIFF('year', date_of_birth, CURRENT_DATE) - t.ssn_age_mismatch_years)
            THEN 1 ELSE 0
        END                                                 AS ssn_age_mismatch_flag
    FROM normalized_applications
    CROSS JOIN thresholds t
),

-- Coherence check 2: SSN reuse — same SSN hash on multiple applications
ssn_reuse AS (
    SELECT
        ssn_hash,
        COUNT(DISTINCT applicant_id)                        AS distinct_applicants,
        COUNT(DISTINCT application_id)                      AS application_count,
        LISTAGG(applicant_id, ', ')
            WITHIN GROUP (ORDER BY application_timestamp)   AS applicant_ids
    FROM normalized_applications
    WHERE ssn_hash IS NOT NULL
    GROUP BY 1
),

-- Coherence check 3: thin file vs stated income mismatch
thin_file_income AS (
    SELECT
        application_id,
        applicant_id,
        credit_file_age_months,
        stated_annual_income,
        CASE
            WHEN credit_file_age_months <= t.thin_file_threshold_months
             AND stated_annual_income >= 75000
            THEN 1 ELSE 0
        END                                                 AS thin_file_high_income_flag
    FROM normalized_applications
    CROSS JOIN thresholds t
),

-- Coherence check 4: contact tenure (phone and email age)
contact_tenure AS (
    SELECT
        application_id,
        applicant_id,
        phone_tenure_days,
        email_tenure_days,
        CASE
            WHEN phone_tenure_days IS NOT NULL
             AND phone_tenure_days < t.min_phone_tenure_days THEN 1 ELSE 0
        END                                                 AS new_phone_flag,
        CASE
            WHEN email_tenure_days IS NOT NULL
             AND email_tenure_days < t.min_email_tenure_days THEN 1 ELSE 0
        END                                                 AS new_email_flag
    FROM normalized_applications
    CROSS JOIN thresholds t
),

-- Coherence check 5: name/SSN match score below threshold
kyc_score_flags AS (
    SELECT
        application_id,
        applicant_id,
        name_ssn_match_score,
        address_match_score,
        CASE
            WHEN name_ssn_match_score IS NOT NULL
             AND name_ssn_match_score < t.min_name_ssn_score THEN 1 ELSE 0
        END                                                 AS name_ssn_mismatch_flag
    FROM normalized_applications
    CROSS JOIN thresholds t
),

-- Combine all coherence checks
combined_flags AS (
    SELECT
        a.application_id,
        a.applicant_id,
        a.ssn_hash,
        a.date_of_birth,
        a.application_timestamp,
        a.credit_file_age_months,
        a.stated_annual_income,
        a.ip_address,
        a.device_fingerprint,
        a.name_ssn_match_score,
        a.phone_tenure_days,
        a.email_tenure_days,
        -- Individual flags
        sac.ssn_age_mismatch_flag,
        COALESCE(sr.distinct_applicants, 1)                 AS ssn_distinct_applicants,
        CASE WHEN COALESCE(sr.distinct_applicants, 1) > 1
             THEN 1 ELSE 0 END                              AS ssn_reuse_flag,
        tfi.thin_file_high_income_flag,
        ct.new_phone_flag,
        ct.new_email_flag,
        kf.name_ssn_mismatch_flag,
        -- Total coherence failures
        (sac.ssn_age_mismatch_flag
         + CASE WHEN COALESCE(sr.distinct_applicants, 1) > 1 THEN 1 ELSE 0 END
         + tfi.thin_file_high_income_flag
         + ct.new_phone_flag
         + ct.new_email_flag
         + kf.name_ssn_mismatch_flag)                       AS coherence_failure_count
    FROM normalized_applications a
    JOIN ssn_age_coherence sac ON a.application_id = sac.application_id
    LEFT JOIN ssn_reuse sr ON a.ssn_hash = sr.ssn_hash
    JOIN thin_file_income tfi ON a.application_id = tfi.application_id
    JOIN contact_tenure ct ON a.application_id = ct.application_id
    JOIN kyc_score_flags kf ON a.application_id = kf.application_id
    CROSS JOIN thresholds t
    WHERE (sac.ssn_age_mismatch_flag
           + CASE WHEN COALESCE(sr.distinct_applicants, 1) > 1 THEN 1 ELSE 0 END
           + tfi.thin_file_high_income_flag
           + ct.new_phone_flag
           + ct.new_email_flag
           + kf.name_ssn_mismatch_flag) >= t.min_coherence_failures
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    application_id,
    applicant_id,
    application_timestamp,
    coherence_failure_count,

    -- INDIVIDUAL FLAGS
    ssn_age_mismatch_flag,
    ssn_reuse_flag,
    ssn_distinct_applicants,
    thin_file_high_income_flag,
    credit_file_age_months,
    stated_annual_income,
    new_phone_flag,
    phone_tenure_days,
    new_email_flag,
    email_tenure_days,
    name_ssn_mismatch_flag,
    name_ssn_match_score,
    ip_address,

    -- CONFIDENCE
    CASE
        WHEN coherence_failure_count >= 4               THEN 'HIGH — Strong Synthetic Indicators'
        WHEN coherence_failure_count >= 3               THEN 'HIGH — Multiple Coherence Failures'
        WHEN coherence_failure_count = 2                THEN 'MEDIUM — Dual Coherence Failure'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'Synthetic Identity Detection'                      AS signal_name,
    'Application ' || application_id
        || ' failed ' || coherence_failure_count::VARCHAR
        || ' of 6 identity coherence checks: '
        || CASE WHEN ssn_age_mismatch_flag = 1 THEN '[SSN/Age Mismatch] ' ELSE '' END
        || CASE WHEN ssn_reuse_flag = 1 THEN '[SSN Reused Across '
               || ssn_distinct_applicants::VARCHAR || ' Applicants] ' ELSE '' END
        || CASE WHEN thin_file_high_income_flag = 1 THEN '[Thin File + High Income] ' ELSE '' END
        || CASE WHEN new_phone_flag = 1 THEN '[New Phone: '
               || phone_tenure_days::VARCHAR || ' days] ' ELSE '' END
        || CASE WHEN new_email_flag = 1 THEN '[New Email: '
               || email_tenure_days::VARCHAR || ' days] ' ELSE '' END
        || CASE WHEN name_ssn_mismatch_flag = 1 THEN '[Name/SSN Mismatch Score: '
               || ROUND(name_ssn_match_score, 0)::VARCHAR || '] ' ELSE '' END
                                                        AS glass_box_verdict

FROM combined_flags
ORDER BY signal_confidence, coherence_failure_count DESC;

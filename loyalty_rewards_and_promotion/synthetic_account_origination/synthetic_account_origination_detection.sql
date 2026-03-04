-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: SYNTHETIC ACCOUNT ORIGINATION
-- =============================================================================
-- File:     synthetic_account_origination_detection.sql
-- Signal:   L08 of 10 — Loyalty & Rewards
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Newly enrolled loyalty accounts that skip the normal member engagement
-- ramp — trial purchase, gradual accrual, occasional redemption — and
-- immediately proceed to high-value redemption activity. Synthetic
-- accounts are created at scale to extract signup bonuses, referral
-- credits, or first-redemption offers without any intent of genuine
-- long-term membership.
--
-- BEHAVIORAL TELL:
-- Organic new members explore the program gradually. They make a few
-- purchases, check their balance, redeem something small, and build
-- engagement over time. Synthetic accounts go straight to extraction:
-- sign up, claim welcome bonus, redeem maximum allowed value,
-- go dormant or disappear. The absence of an engagement arc is the signal.
--
-- DATA REQUIREMENTS:
-- Requires: member_id, enrollment_timestamp, first_accrual_timestamp,
--           first_redemption_timestamp, total_points_redeemed,
--           welcome_bonus_claimed
-- Improves with: ip_address, device_fingerprint, email_domain
--
-- TUNING PARAMETERS:
-- * days_to_first_redemption  — redemption within N days of enrollment = synthetic (default: 7)
-- * min_redemption_value      — minimum redemption to flag (default: $25)
-- * welcome_bonus_only_flag   — flag accounts that redeem only welcome bonus points
--
-- TYPICAL EXPOSURE: $20,000 — $200,000
-- =============================================================================

WITH normalized_members AS (
    SELECT
        member_id               AS member_id,
        enrollment_timestamp    AS enrollment_timestamp,
        welcome_bonus_points    AS welcome_bonus_points,    -- expected: FLOAT (0 if no welcome bonus)
        ip_address              AS enrollment_ip,
        device_fingerprint      AS enrollment_device,
        LOWER(SPLIT_PART(email, '@', 2))
                                AS email_domain
    FROM your_members_table         -- << CHANGE THIS
    WHERE enrollment_timestamp >= DATEADD('year', -1, CURRENT_DATE)
),

normalized_accruals AS (
    SELECT
        member_id,
        MIN(accrual_timestamp)  AS first_accrual_timestamp,
        SUM(CASE WHEN accrual_reason = 'purchase' THEN points_earned ELSE 0 END)
                                AS organic_points_earned,
        COUNT(CASE WHEN accrual_reason = 'purchase' THEN 1 END)
                                AS purchase_count
    FROM your_accrual_ledger_table  -- << CHANGE THIS
    GROUP BY 1
),

normalized_redemptions AS (
    SELECT
        member_id,
        MIN(redemption_timestamp)       AS first_redemption_timestamp,
        SUM(redemption_value)           AS total_redemption_value,
        COUNT(*)                        AS redemption_count
    FROM your_redemption_ledger_table   -- << CHANGE THIS
    GROUP BY 1
),

thresholds AS (
    SELECT
        7       AS days_to_first_redemption,    -- Redemption within 7 days of enrollment
        25      AS min_redemption_value,
        3       AS min_purchases_expected       -- Expected purchases before first redemption
),

combined AS (
    SELECT
        m.member_id,
        m.enrollment_timestamp,
        m.welcome_bonus_points,
        m.enrollment_ip,
        m.enrollment_device,
        m.email_domain,
        a.first_accrual_timestamp,
        a.organic_points_earned,
        a.purchase_count,
        r.first_redemption_timestamp,
        r.total_redemption_value,
        r.redemption_count,
        DATEDIFF('day', m.enrollment_timestamp, r.first_redemption_timestamp)
                                                        AS days_enrollment_to_redemption,
        t.days_to_first_redemption,
        t.min_redemption_value,
        t.min_purchases_expected
    FROM normalized_members m
    LEFT JOIN normalized_accruals a ON m.member_id = a.member_id
    LEFT JOIN normalized_redemptions r ON m.member_id = r.member_id
    CROSS JOIN thresholds t
    WHERE r.first_redemption_timestamp IS NOT NULL
      AND r.total_redemption_value >= t.min_redemption_value
)

SELECT
    member_id,
    enrollment_timestamp,
    first_accrual_timestamp,
    first_redemption_timestamp,
    days_enrollment_to_redemption,
    organic_points_earned,
    purchase_count,
    welcome_bonus_points,
    total_redemption_value,
    redemption_count,
    enrollment_ip,
    enrollment_device,
    email_domain,

    CASE
        WHEN days_enrollment_to_redemption <= 3
         AND purchase_count <= 1                        THEN 'HIGH — Immediate Extraction'
        WHEN days_enrollment_to_redemption <= days_to_first_redemption
         AND COALESCE(organic_points_earned, 0) = 0    THEN 'HIGH — Zero Organic Activity'
        WHEN days_enrollment_to_redemption <= days_to_first_redemption
                                                        THEN 'MEDIUM — Rapid Redemption'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'Synthetic Account Origination'                     AS signal_name,
    'Member ' || member_id
        || ' enrolled and redeemed $'
        || ROUND(total_redemption_value, 0)::VARCHAR
        || ' in value within '
        || days_enrollment_to_redemption::VARCHAR
        || ' days. Organic purchases before redemption: '
        || COALESCE(purchase_count, 0)::VARCHAR
        || '. Welcome bonus claimed: '
        || COALESCE(welcome_bonus_points, 0)::VARCHAR || ' points.'
                                                        AS glass_box_verdict

FROM combined
WHERE
    days_enrollment_to_redemption <= days_to_first_redemption
    OR COALESCE(organic_points_earned, 0) = 0

ORDER BY signal_confidence, total_redemption_value DESC;

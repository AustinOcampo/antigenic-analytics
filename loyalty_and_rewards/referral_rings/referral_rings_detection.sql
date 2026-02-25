-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: REFERRAL RING DETECTION
-- =============================================================================
-- File:     referral_rings_detection.sql
-- Signal:   L03 of 10 — Loyalty & Rewards
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Clusters of accounts referring each other in circular or hub-and-spoke
-- patterns to repeatedly farm referral bonuses without generating genuine
-- new customer acquisition. Referral fraud is one of the most expensive
-- loyalty exploits because the bonus is often high (designed to incentivize
-- real customers to recruit) and the circular structure means the same
-- people extract value over and over from a program designed to be one-time.
--
-- BEHAVIORAL TELL:
-- Legitimate referral patterns are tree-shaped: A refers B, C, D who each
-- refer their own networks. Fraudulent referral patterns are circular or
-- hub-dominated: A refers B, B refers C, C refers A — or a single hub
-- account generates dozens of referrals that all share device, IP, or
-- address identifiers. The graph structure betrays the fraud.
--
-- DATA REQUIREMENTS:
-- Requires: member_id, referred_by_member_id, enrollment_timestamp,
--           referral_bonus_awarded, referral_bonus_amount
-- Improves with: ip_address_at_enrollment, device_fingerprint_at_enrollment,
--               email_domain, shipping_address
--
-- TUNING PARAMETERS:
-- * min_cluster_size         — minimum accounts in a referral cluster (default: 3)
-- * min_cluster_bonus_value  — minimum total bonus extracted (default: $50)
-- * circular_depth           — how many hops to check for circularity (default: 3)
--
-- TYPICAL EXPOSURE: $25,000 — $500,000
-- =============================================================================

WITH normalized_members AS (

    SELECT
        member_id               AS member_id,               -- expected: VARCHAR
        referred_by_member_id   AS referred_by,             -- expected: VARCHAR (NULL if organic)
        enrollment_timestamp    AS enrollment_timestamp,    -- expected: TIMESTAMP_NTZ
        referral_bonus_awarded  AS bonus_awarded,           -- expected: BOOLEAN / INTEGER (1/0)
        referral_bonus_amount   AS bonus_amount,            -- expected: FLOAT
        ip_address              AS enrollment_ip,           -- expected: VARCHAR (NULL ok)
        device_fingerprint      AS enrollment_device,       -- expected: VARCHAR (NULL ok)
        LOWER(SPLIT_PART(email, '@', 2))
                                AS email_domain,            -- expected: VARCHAR (NULL ok)
        LOWER(TRIM(shipping_address))
                                AS shipping_address         -- expected: VARCHAR (NULL ok)

    FROM your_members_table         -- << CHANGE THIS

    WHERE referred_by_member_id IS NOT NULL     -- only referred members

),

thresholds AS (
    SELECT
        3       AS min_cluster_size,
        50      AS min_cluster_bonus_value
),

-- Direct referral pairs
referral_pairs AS (
    SELECT
        referred_by             AS referrer_id,
        member_id               AS referred_id,
        enrollment_timestamp,
        bonus_amount,
        enrollment_ip,
        enrollment_device,
        email_domain,
        shipping_address
    FROM normalized_members
),

-- Detect circular referrals: A→B→A or A→B→C→A (depth 2-3)
circular_2hop AS (
    SELECT
        a.referrer_id           AS member_a,
        a.referred_id           AS member_b,
        b.referred_id           AS member_c,
        'circular_2hop'         AS pattern_type
    FROM referral_pairs a
    JOIN referral_pairs b
        ON  a.referred_id = b.referrer_id
        AND b.referred_id = a.referrer_id   -- B refers back to A
),

circular_3hop AS (
    SELECT
        a.referrer_id           AS member_a,
        a.referred_id           AS member_b,
        b.referred_id           AS member_c,
        c.referred_id           AS member_d,
        'circular_3hop'         AS pattern_type
    FROM referral_pairs a
    JOIN referral_pairs b ON a.referred_id = b.referrer_id
    JOIN referral_pairs c ON b.referred_id = c.referrer_id
        AND c.referred_id = a.referrer_id   -- C refers back to A
),

-- Hub accounts: single referrer generating many referrals
hub_referrers AS (
    SELECT
        referrer_id,
        COUNT(DISTINCT referred_id)             AS referral_count,
        SUM(bonus_amount)                       AS total_bonus_extracted,
        COUNT(DISTINCT enrollment_ip)           AS distinct_ips,
        COUNT(DISTINCT enrollment_device)       AS distinct_devices,
        COUNT(DISTINCT email_domain)            AS distinct_email_domains,
        COUNT(DISTINCT shipping_address)        AS distinct_addresses,
        MIN(enrollment_timestamp)               AS first_referral,
        MAX(enrollment_timestamp)               AS last_referral
    FROM referral_pairs
    GROUP BY 1
),

-- Flag hubs where referred accounts share too many identifiers
suspicious_hubs AS (
    SELECT
        h.*,
        CASE
            WHEN h.referral_count >= 10
             AND h.distinct_ips <= h.referral_count * 0.3   THEN 'HIGH — Hub Farm'
            WHEN h.referral_count >= 5
             AND h.distinct_devices <= h.referral_count * 0.4 THEN 'HIGH — Device Cluster'
            WHEN h.referral_count >= t.min_cluster_size
             AND h.total_bonus_extracted >= t.min_cluster_bonus_value THEN 'MEDIUM — Hub Pattern'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM hub_referrers h
    CROSS JOIN thresholds t
    WHERE h.referral_count >= t.min_cluster_size
      AND h.total_bonus_extracted >= t.min_cluster_bonus_value
)

-- Output 1: Suspicious hub referrers
SELECT
    referrer_id                                             AS member_id,
    'hub_referrer'                                          AS pattern_type,
    referral_count,
    total_bonus_extracted,
    distinct_ips,
    distinct_devices,
    distinct_email_domains,
    distinct_addresses,
    first_referral,
    last_referral,
    signal_confidence,
    'Referral Ring Detection'                               AS signal_name,
    'Member ' || referrer_id
        || ' generated ' || referral_count::VARCHAR
        || ' referrals extracting $'
        || ROUND(total_bonus_extracted, 0)::VARCHAR
        || ' in bonuses. Referred accounts shared only '
        || distinct_ips::VARCHAR || ' IPs and '
        || distinct_devices::VARCHAR || ' devices across '
        || referral_count::VARCHAR || ' signups.'           AS glass_box_verdict

FROM suspicious_hubs
WHERE signal_confidence IN ('HIGH — Hub Farm',
                            'HIGH — Device Cluster',
                            'MEDIUM — Hub Pattern')

UNION ALL

-- Output 2: Circular referral pairs
SELECT
    member_a                                                AS member_id,
    pattern_type,
    2                                                       AS referral_count,
    NULL                                                    AS total_bonus_extracted,
    NULL, NULL, NULL, NULL, NULL, NULL,
    'HIGH — Circular Referral'                              AS signal_confidence,
    'Referral Ring Detection'                               AS signal_name,
    'Members ' || member_a || ' and ' || member_b
        || ' referred each other — circular referral detected.'
                                                            AS glass_box_verdict

FROM circular_2hop

ORDER BY signal_confidence, total_bonus_extracted DESC NULLS LAST;

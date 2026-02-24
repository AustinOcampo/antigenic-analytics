-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: NETWORK CLUSTERING (SHARED IDENTIFIERS)
-- =============================================================================
-- File:     network_clustering_detection.sql
-- Signal:   04 of 10 — Procurement & AP
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Multiple vendors who appear independent but share identifiers — same address,
-- phone number, bank routing number, contact name, or tax ID variants.
-- Shell company fraud depends on vendor diversity as camouflage. This signal
-- collapses that camouflage by finding the connective tissue between vendors.
--
-- BEHAVIORAL TELL:
-- Legitimate vendors occasionally share a zip code or common bank.
-- They do not share a suite number, a contact name, AND a bank routing number.
-- The more identifiers that overlap, the higher the confidence these vendors
-- are operationally connected — and the total spend across the cluster is
-- your true exposure, not just one vendor's invoices.
--
-- DATA REQUIREMENTS:
-- Requires: vendor_id, vendor_name, invoice_amount
-- Improves with: vendor_address, vendor_tax_id, vendor_bank_routing,
--                contact_name, contact_email_domain
-- NOTE: This signal degrades significantly with poor vendor master data quality.
--       A vendor master cleaning pass is recommended before running this signal.
--
-- TUNING PARAMETERS:
-- * min_shared_identifiers   — how many identifiers must match to flag (default: 2)
-- * min_cluster_spend        — minimum combined cluster spend to report (default: $25,000)
--
-- TYPICAL EXPOSURE RANGE: $200,000 — $5,000,000 (entire cluster spend)
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_vendors AS (

    SELECT DISTINCT
        vendor_id               AS vendor_id,               -- expected: VARCHAR
        vendor_name             AS vendor_name,             -- expected: VARCHAR
        -- Normalize address: strip punctuation, lowercase, trim spaces
        -- This reduces false negatives from formatting differences
        LOWER(TRIM(REGEXP_REPLACE(vendor_address, '[^a-zA-Z0-9 ]', '')))
                                AS vendor_address_normalized, -- expected: VARCHAR (NULL ok)
        vendor_tax_id           AS vendor_tax_id,           -- expected: VARCHAR (NULL ok)
        vendor_bank_routing     AS vendor_bank_routing,     -- expected: VARCHAR (NULL ok)
        LOWER(TRIM(contact_name))
                                AS contact_name_normalized, -- expected: VARCHAR (NULL ok)
        -- Extract email domain only (not full address) for domain-level matching
        LOWER(SPLIT_PART(contact_email, '@', 2))
                                AS contact_email_domain     -- expected: VARCHAR (NULL ok)

    FROM your_vendor_master_table   -- << CHANGE THIS (vendor master / supplier table)
    WHERE vendor_status NOT IN ('INACTIVE', 'ARCHIVED')     -- exclude dormant vendors

),

normalized_spend AS (

    SELECT
        vendor_id               AS vendor_id,               -- expected: VARCHAR
        SUM(invoice_amount)     AS total_spend              -- expected: FLOAT

    FROM your_internal_table_name   -- << CHANGE THIS (AP / invoice table)
    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')
    GROUP BY 1

),

thresholds AS (
    SELECT
        2       AS min_shared_identifiers,      -- Minimum matching identifiers to flag connection
        25000   AS min_cluster_spend            -- Minimum combined cluster spend to surface
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Self-join vendors on each shared identifier separately
-- This produces one row per (vendor_a, vendor_b, shared_identifier_type)
shared_address AS (
    SELECT
        a.vendor_id AS vendor_id_a, b.vendor_id AS vendor_id_b,
        'shared_address' AS identifier_type, a.vendor_address_normalized AS shared_value
    FROM normalized_vendors a
    JOIN normalized_vendors b
        ON  a.vendor_address_normalized = b.vendor_address_normalized
        AND a.vendor_id < b.vendor_id   -- prevent duplicate pairs
        AND a.vendor_address_normalized IS NOT NULL
        AND LENGTH(a.vendor_address_normalized) > 10    -- avoid matching on blank/short strings
),

shared_tax_id AS (
    SELECT
        a.vendor_id AS vendor_id_a, b.vendor_id AS vendor_id_b,
        'shared_tax_id' AS identifier_type, a.vendor_tax_id AS shared_value
    FROM normalized_vendors a
    JOIN normalized_vendors b
        ON  a.vendor_tax_id = b.vendor_tax_id
        AND a.vendor_id < b.vendor_id
        AND a.vendor_tax_id IS NOT NULL
),

shared_bank_routing AS (
    SELECT
        a.vendor_id AS vendor_id_a, b.vendor_id AS vendor_id_b,
        'shared_bank_routing' AS identifier_type, a.vendor_bank_routing AS shared_value
    FROM normalized_vendors a
    JOIN normalized_vendors b
        ON  a.vendor_bank_routing = b.vendor_bank_routing
        AND a.vendor_id < b.vendor_id
        AND a.vendor_bank_routing IS NOT NULL
),

shared_contact AS (
    SELECT
        a.vendor_id AS vendor_id_a, b.vendor_id AS vendor_id_b,
        'shared_contact_name' AS identifier_type, a.contact_name_normalized AS shared_value
    FROM normalized_vendors a
    JOIN normalized_vendors b
        ON  a.contact_name_normalized = b.contact_name_normalized
        AND a.vendor_id < b.vendor_id
        AND a.contact_name_normalized IS NOT NULL
        AND LENGTH(a.contact_name_normalized) > 3
),

shared_email_domain AS (
    SELECT
        a.vendor_id AS vendor_id_a, b.vendor_id AS vendor_id_b,
        'shared_email_domain' AS identifier_type, a.contact_email_domain AS shared_value
    FROM normalized_vendors a
    JOIN normalized_vendors b
        ON  a.contact_email_domain = b.contact_email_domain
        AND a.vendor_id < b.vendor_id
        AND a.contact_email_domain IS NOT NULL
        -- Exclude common free email domains — these are meaningless as shared identifiers
        AND a.contact_email_domain NOT IN ('gmail.com','yahoo.com','hotmail.com','outlook.com')
),

-- Union all shared identifier pairs
all_shared_identifiers AS (
    SELECT * FROM shared_address
    UNION ALL SELECT * FROM shared_tax_id
    UNION ALL SELECT * FROM shared_bank_routing
    UNION ALL SELECT * FROM shared_contact
    UNION ALL SELECT * FROM shared_email_domain
),

-- Count how many identifiers each vendor pair shares
pair_summary AS (
    SELECT
        vendor_id_a,
        vendor_id_b,
        COUNT(DISTINCT identifier_type)             AS shared_identifier_count,
        LISTAGG(identifier_type || ': ' || shared_value, ' | ')
            WITHIN GROUP (ORDER BY identifier_type) AS shared_identifier_detail
    FROM all_shared_identifiers
    GROUP BY 1, 2
),

-- Join vendor names and spend back to pairs
enriched_pairs AS (
    SELECT
        p.vendor_id_a,
        va.vendor_name                              AS vendor_name_a,
        COALESCE(sa.total_spend, 0)                 AS spend_vendor_a,
        p.vendor_id_b,
        vb.vendor_name                              AS vendor_name_b,
        COALESCE(sb.total_spend, 0)                 AS spend_vendor_b,
        p.shared_identifier_count,
        p.shared_identifier_detail,
        COALESCE(sa.total_spend, 0) + COALESCE(sb.total_spend, 0)
                                                    AS combined_cluster_spend
    FROM pair_summary p
    JOIN normalized_vendors va ON p.vendor_id_a = va.vendor_id
    JOIN normalized_vendors vb ON p.vendor_id_b = vb.vendor_id
    LEFT JOIN normalized_spend sa ON p.vendor_id_a = sa.vendor_id
    LEFT JOIN normalized_spend sb ON p.vendor_id_b = sb.vendor_id
    CROSS JOIN thresholds t
    WHERE
        p.shared_identifier_count >= t.min_shared_identifiers
        AND COALESCE(sa.total_spend, 0) + COALESCE(sb.total_spend, 0) >= t.min_cluster_spend
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    vendor_id_a,
    vendor_name_a,
    spend_vendor_a,
    vendor_id_b,
    vendor_name_b,
    spend_vendor_b,
    combined_cluster_spend,
    shared_identifier_count,
    shared_identifier_detail,

    -- CONFIDENCE SCORING
    CASE
        WHEN shared_identifier_count >= 4 THEN 'HIGH — Strong Connection'
        WHEN shared_identifier_count = 3  THEN 'HIGH — Multiple Overlaps'
        WHEN shared_identifier_count = 2  THEN 'MEDIUM — Dual Match'
        ELSE 'LOW'
    END                                             AS signal_confidence,

    'Network Clustering'                            AS signal_name,

    vendor_name_a || ' and ' || vendor_name_b
        || ' share ' || shared_identifier_count::VARCHAR
        || ' identifiers: ' || shared_identifier_detail
        || '. Combined spend across both vendors: $'
        || ROUND(combined_cluster_spend, 0)::VARCHAR
        || '. If connected, total cluster is the true exposure.'
                                                    AS glass_box_verdict

FROM enriched_pairs
ORDER BY shared_identifier_count DESC, combined_cluster_spend DESC;


-- =============================================================================
-- INVESTIGATIVE NEXT STEPS
-- =============================================================================
-- 1. Pull full vendor master record for each flagged pair from procurement system
-- 2. Check Secretary of State business registry for shared ownership / registered agent
-- 3. Review vendor onboarding documentation — who sponsored each vendor's addition?
-- 4. Cross-reference with Signal 07 (Approval Chain Compression) — did the same
--    approver authorize both vendors?
-- 5. Dollar exposure = combined_cluster_spend for confirmed shell clusters
-- =============================================================================

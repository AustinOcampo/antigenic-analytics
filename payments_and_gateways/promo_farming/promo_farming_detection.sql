-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: PROMO FARMING
-- =============================================================================
-- File:     promo_farming_detection.sql
-- Signal:   P02 of 10 — Payments & Gateways
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Coordinated extraction of promotional value — discount codes, referral credits,
-- first-order promos, free shipping thresholds — across multiple accounts that
-- are operationally linked. Promo farmers create account clusters to redeem
-- single-use offers repeatedly, often reselling discounted goods or simply
-- extracting the credit directly.
--
-- BEHAVIORAL TELL:
-- Legitimate customers use one promo code on one account. Promo farmers
-- use the same device, IP, address, or payment method across multiple accounts
-- to redeem the same offer over and over. The accounts look independent —
-- until you look at the connective tissue between them.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, customer_id, discount_code, discount_amount,
--           transaction_timestamp, order_amount
-- Improves with: ip_address, device_fingerprint, shipping_address, email_domain
--
-- TUNING PARAMETERS:
-- * min_accounts_per_cluster     — accounts sharing an identifier to flag (default: 3)
-- * min_promo_discount_total     — minimum extracted discount value (default: $100)
-- * lookback_days                — window for cluster detection (default: 90 days)
--
-- TYPICAL EXPOSURE: $25,000 — $250,000
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,          -- expected: VARCHAR
        customer_id             AS customer_id,             -- expected: VARCHAR
        order_amount            AS order_amount,            -- expected: FLOAT
        discount_code           AS discount_code,           -- expected: VARCHAR (NULL if no discount)
        discount_amount         AS discount_amount,         -- expected: FLOAT (0 if no discount)
        created_at              AS transaction_timestamp,   -- expected: TIMESTAMP_NTZ
        ip_address              AS ip_address,              -- expected: VARCHAR (NULL ok)
        device_fingerprint      AS device_fingerprint,      -- expected: VARCHAR (NULL ok)
        shipping_address        AS shipping_address,        -- expected: VARCHAR (NULL ok)
        -- Extract email domain for cluster detection
        LOWER(SPLIT_PART(customer_email, '@', 2))
                                AS email_domain,            -- expected: VARCHAR (NULL ok)
        customer_email          AS customer_email           -- expected: VARCHAR (NULL ok)

    FROM your_orders_table          -- << CHANGE THIS

    WHERE
        created_at >= DATEADD('day', -90, CURRENT_DATE)
        AND discount_amount > 0         -- Only transactions where a promo was applied

),

thresholds AS (
    SELECT
        3       AS min_accounts_per_cluster,    -- Minimum linked accounts to flag
        100     AS min_promo_discount_total,    -- Minimum total discount extracted
        90      AS lookback_days               -- Rolling window for cluster detection
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Find accounts sharing the same IP address
shared_ip_clusters AS (
    SELECT
        a.customer_id AS customer_id_a,
        b.customer_id AS customer_id_b,
        'shared_ip' AS link_type,
        a.ip_address AS shared_value
    FROM normalized_transactions a
    JOIN normalized_transactions b
        ON  a.ip_address = b.ip_address
        AND a.customer_id < b.customer_id
        AND a.ip_address IS NOT NULL
        AND a.ip_address NOT IN ('127.0.0.1', '::1')    -- exclude localhost
),

-- Find accounts sharing the same device fingerprint
shared_device_clusters AS (
    SELECT
        a.customer_id AS customer_id_a,
        b.customer_id AS customer_id_b,
        'shared_device' AS link_type,
        a.device_fingerprint AS shared_value
    FROM normalized_transactions a
    JOIN normalized_transactions b
        ON  a.device_fingerprint = b.device_fingerprint
        AND a.customer_id < b.customer_id
        AND a.device_fingerprint IS NOT NULL
),

-- Find accounts sharing the same shipping address
shared_address_clusters AS (
    SELECT
        a.customer_id AS customer_id_a,
        b.customer_id AS customer_id_b,
        'shared_shipping_address' AS link_type,
        a.shipping_address AS shared_value
    FROM normalized_transactions a
    JOIN normalized_transactions b
        ON  LOWER(TRIM(a.shipping_address)) = LOWER(TRIM(b.shipping_address))
        AND a.customer_id < b.customer_id
        AND a.shipping_address IS NOT NULL
),

-- Find accounts sharing non-free email domains
shared_email_domain_clusters AS (
    SELECT
        a.customer_id AS customer_id_a,
        b.customer_id AS customer_id_b,
        'shared_email_domain' AS link_type,
        a.email_domain AS shared_value
    FROM normalized_transactions a
    JOIN normalized_transactions b
        ON  a.email_domain = b.email_domain
        AND a.customer_id < b.customer_id
        AND a.email_domain IS NOT NULL
        AND a.email_domain NOT IN ('gmail.com','yahoo.com','hotmail.com',
                                   'outlook.com','icloud.com','protonmail.com')
),

-- Union all links
all_links AS (
    SELECT * FROM shared_ip_clusters
    UNION ALL SELECT * FROM shared_device_clusters
    UNION ALL SELECT * FROM shared_address_clusters
    UNION ALL SELECT * FROM shared_email_domain_clusters
),

-- Count distinct accounts linked to each customer
customer_cluster_size AS (
    SELECT
        customer_id_a AS customer_id,
        COUNT(DISTINCT customer_id_b) AS linked_account_count,
        COUNT(DISTINCT link_type) AS link_type_count,
        LISTAGG(DISTINCT link_type, ', ') AS link_types_found
    FROM all_links
    GROUP BY 1
),

-- Promo usage summary per customer
customer_promo_stats AS (
    SELECT
        customer_id,
        COUNT(DISTINCT discount_code)               AS distinct_promo_codes_used,
        COUNT(DISTINCT transaction_id)              AS promo_order_count,
        SUM(discount_amount)                        AS total_discount_extracted,
        SUM(order_amount)                           AS total_order_value,
        ROUND(100.0 * SUM(discount_amount)
            / NULLIF(SUM(order_amount + discount_amount), 0), 1)
                                                    AS effective_discount_rate_pct,
        MIN(transaction_timestamp)                  AS first_promo_use,
        MAX(transaction_timestamp)                  AS last_promo_use,
        LISTAGG(DISTINCT discount_code, ', ')       AS promo_codes_used
    FROM normalized_transactions
    GROUP BY 1
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    p.customer_id,
    c.linked_account_count,
    c.link_type_count,
    c.link_types_found,
    p.distinct_promo_codes_used,
    p.promo_order_count,
    p.total_discount_extracted,
    p.total_order_value,
    p.effective_discount_rate_pct,
    p.promo_codes_used,
    p.first_promo_use,
    p.last_promo_use,

    CASE
        WHEN c.link_type_count >= 3
         AND c.linked_account_count >= 5               THEN 'HIGH — Coordinated Farm'
        WHEN c.link_type_count >= 2
         AND c.linked_account_count >= 3               THEN 'HIGH — Linked Cluster'
        WHEN c.linked_account_count >= t.min_accounts_per_cluster
                                                        THEN 'MEDIUM — Shared Identifier'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'Promo Farming'                                     AS signal_name,
    'Customer ' || p.customer_id
        || ' is linked to ' || c.linked_account_count::VARCHAR
        || ' other accounts via: ' || c.link_types_found
        || '. Cluster has extracted $'
        || ROUND(p.total_discount_extracted, 0)::VARCHAR
        || ' in discounts across ' || p.promo_order_count::VARCHAR
        || ' orders using codes: ' || p.promo_codes_used
                                                        AS glass_box_verdict

FROM customer_promo_stats p
JOIN customer_cluster_size c ON p.customer_id = c.customer_id
CROSS JOIN thresholds t
WHERE
    c.linked_account_count >= t.min_accounts_per_cluster
    AND p.total_discount_extracted >= t.min_promo_discount_total

ORDER BY signal_confidence, p.total_discount_extracted DESC;

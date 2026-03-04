-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: SELLER COLLUSION RINGS
-- =============================================================================
-- File:     seller_collusion_rings_detection.sql
-- Signal:   M01 of 10 — Marketplace & Platform Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Groups of seller accounts operating in coordination to inflate ratings,
-- suppress competitors, and manipulate search ranking. Collusion rings share
-- operational fingerprints — overlapping IP addresses, device IDs, bank
-- accounts, or registration metadata — while presenting themselves as
-- independent sellers. The coordination surfaces through synchronized
-- behavioral patterns: listing at the same times, pricing in lockstep,
-- cross-purchasing to inflate review counts, and targeting the same
-- competitor listings with negative actions.
--
-- BEHAVIORAL TELL:
-- Independent sellers behave independently. They list products on their own
-- schedules, price according to their own margins, and attract organic
-- reviews at irregular intervals. Colluding sellers show temporal
-- synchronization — they act in bursts, often within minutes of each other.
-- Their buyer pools overlap unnaturally, and their shared infrastructure
-- (IP, device, bank) creates a graph that legitimate sellers never form.
--
-- DATA REQUIREMENTS:
-- Requires: seller_id, seller_registration_date, seller_ip_address,
--           seller_device_id, seller_bank_account, listing_id,
--           listing_created_at, transaction_id, buyer_id,
--           transaction_timestamp, transaction_amount
-- Optional: seller_email_domain, seller_phone, seller_address,
--           listing_category, review_id, review_rating
--
-- TUNING PARAMETERS:
-- * min_shared_attributes    — minimum shared infrastructure to link sellers (default: 2)
-- * min_cluster_size         — minimum sellers in a ring to flag (default: 3)
-- * sync_window_minutes      — time window for synchronized listing activity (default: 30)
-- * min_buyer_overlap_pct    — minimum buyer overlap between sellers to flag (default: 25%)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $50K–$1M per ring
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- This is the only section you edit.
-- =============================================================================

WITH normalized_sellers AS (

    SELECT
        -- SELLER IDENTIFIERS
        seller_id               AS seller_id,               -- expected: VARCHAR / STRING
        created_at              AS seller_registration_date, -- expected: DATE / TIMESTAMP
        email_domain            AS seller_email_domain,      -- expected: VARCHAR (domain portion only)

        -- SELLER INFRASTRUCTURE
        ip_address              AS seller_ip_address,        -- expected: VARCHAR
        device_id               AS seller_device_id,         -- expected: VARCHAR
        bank_account_hash       AS seller_bank_account,      -- expected: VARCHAR (hashed or tokenized)
        phone_number            AS seller_phone,             -- expected: VARCHAR (NULL if not stored)
        address_line_1          AS seller_address,           -- expected: VARCHAR

    FROM your_seller_table                                   -- << REPLACE WITH YOUR TABLE

),

normalized_listings AS (

    SELECT
        listing_id              AS listing_id,               -- expected: VARCHAR / STRING
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        created_at              AS listing_created_at,        -- expected: TIMESTAMP_NTZ
        category                AS listing_category,         -- expected: VARCHAR
        price                   AS listing_price,            -- expected: FLOAT / NUMBER

    FROM your_listing_table                                  -- << REPLACE WITH YOUR TABLE

),

normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,           -- expected: VARCHAR / STRING
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        buyer_id                AS buyer_id,                 -- expected: VARCHAR / STRING
        created_at              AS transaction_timestamp,     -- expected: TIMESTAMP_NTZ
        amount                  AS transaction_amount,        -- expected: FLOAT / NUMBER

    FROM your_transaction_table                              -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS — Adjust these to match your environment
-- =============================================================================
-- Each threshold has an inline rationale. Defaults are calibrated for
-- mid-market marketplace platforms processing 10K–500K monthly transactions.
-- =============================================================================

thresholds AS (
    SELECT
        2       AS min_shared_attributes,       -- 2+ shared infra signals (IP, device, bank) = likely coordination
        3       AS min_cluster_size,            -- fewer than 3 sellers is a partnership, not a ring
        30      AS sync_window_minutes,         -- independent sellers rarely list within 30 min of each other repeatedly
        25.0    AS min_buyer_overlap_pct,       -- >25% buyer overlap between sellers is far above organic baseline (~2-5%)
        180     AS lookback_days                -- 6 months captures seasonal rings and slow-burn operations
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

-- Step 1: Identify shared infrastructure between seller pairs
seller_infrastructure_links AS (
    SELECT
        a.seller_id                                         AS seller_a,
        b.seller_id                                         AS seller_b,
        SUM(CASE
            WHEN a.seller_ip_address IS NOT NULL
             AND a.seller_ip_address = b.seller_ip_address          THEN 1 ELSE 0 END
          + CASE
            WHEN a.seller_device_id IS NOT NULL
             AND a.seller_device_id = b.seller_device_id            THEN 1 ELSE 0 END
          + CASE
            WHEN a.seller_bank_account IS NOT NULL
             AND a.seller_bank_account = b.seller_bank_account      THEN 1 ELSE 0 END
          + CASE
            WHEN a.seller_email_domain IS NOT NULL
             AND a.seller_email_domain = b.seller_email_domain      THEN 1 ELSE 0 END
          + CASE
            WHEN a.seller_phone IS NOT NULL
             AND a.seller_phone = b.seller_phone                    THEN 1 ELSE 0 END
          + CASE
            WHEN a.seller_address IS NOT NULL
             AND a.seller_address = b.seller_address                THEN 1 ELSE 0 END
        )                                                   AS shared_attribute_count,
        -- Track which attributes are shared for the verdict
        ARRAY_CONSTRUCT_COMPACT(
            CASE WHEN a.seller_ip_address = b.seller_ip_address     THEN 'IP' END,
            CASE WHEN a.seller_device_id = b.seller_device_id       THEN 'DEVICE' END,
            CASE WHEN a.seller_bank_account = b.seller_bank_account THEN 'BANK' END,
            CASE WHEN a.seller_email_domain = b.seller_email_domain THEN 'EMAIL_DOMAIN' END,
            CASE WHEN a.seller_phone = b.seller_phone               THEN 'PHONE' END,
            CASE WHEN a.seller_address = b.seller_address           THEN 'ADDRESS' END
        )                                                   AS shared_attributes
    FROM normalized_sellers a
    INNER JOIN normalized_sellers b
        ON a.seller_id < b.seller_id                        -- avoid duplicates and self-joins
    WHERE a.seller_ip_address = b.seller_ip_address
       OR a.seller_device_id = b.seller_device_id
       OR a.seller_bank_account = b.seller_bank_account
       OR a.seller_email_domain = b.seller_email_domain
       OR a.seller_phone = b.seller_phone
       OR a.seller_address = b.seller_address
),

-- Step 2: Filter to pairs exceeding the shared attribute threshold
linked_pairs AS (
    SELECT
        sil.seller_a,
        sil.seller_b,
        sil.shared_attribute_count,
        sil.shared_attributes
    FROM seller_infrastructure_links sil
    CROSS JOIN thresholds t
    WHERE sil.shared_attribute_count >= t.min_shared_attributes
),

-- Step 3: Build clusters using connected components
-- Each seller is assigned to the lowest-ID seller they are linked to
cluster_seeds AS (
    SELECT seller_a AS seller_id, seller_a AS cluster_root FROM linked_pairs
    UNION
    SELECT seller_b AS seller_id, seller_a AS cluster_root FROM linked_pairs
),

cluster_assignment AS (
    SELECT
        seller_id,
        MIN(cluster_root)                                   AS cluster_id
    FROM cluster_seeds
    GROUP BY seller_id
),

-- Step 4: Compute cluster-level metrics
cluster_metrics AS (
    SELECT
        ca.cluster_id,
        COUNT(DISTINCT ca.seller_id)                        AS cluster_size,
        ARRAY_AGG(DISTINCT ca.seller_id)                    AS cluster_members,
        COUNT(DISTINCT nl.listing_id)                       AS total_listings,
        SUM(nt.transaction_amount)                          AS total_gmv,
        COUNT(DISTINCT nt.transaction_id)                   AS total_transactions,
        COUNT(DISTINCT nt.buyer_id)                         AS distinct_buyers,
        MIN(ns.seller_registration_date)                    AS earliest_registration,
        MAX(ns.seller_registration_date)                    AS latest_registration,
        DATEDIFF('day',
            MIN(ns.seller_registration_date),
            MAX(ns.seller_registration_date))               AS registration_span_days
    FROM cluster_assignment ca
    INNER JOIN normalized_sellers ns
        ON ca.seller_id = ns.seller_id
    LEFT JOIN normalized_listings nl
        ON ca.seller_id = nl.seller_id
        AND nl.listing_created_at >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
    LEFT JOIN normalized_transactions nt
        ON ca.seller_id = nt.seller_id
        AND nt.transaction_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
    GROUP BY ca.cluster_id
),

-- Step 5: Measure buyer overlap within each cluster
-- High buyer overlap = sellers trading with the same buyers = likely wash trading
buyer_overlap AS (
    SELECT
        ca.cluster_id,
        nt.buyer_id,
        COUNT(DISTINCT ca.seller_id)                        AS sellers_sharing_buyer
    FROM cluster_assignment ca
    INNER JOIN normalized_transactions nt
        ON ca.seller_id = nt.seller_id
        AND nt.transaction_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
    GROUP BY ca.cluster_id, nt.buyer_id
),

buyer_overlap_rate AS (
    SELECT
        bo.cluster_id,
        ROUND(100.0 * COUNT(CASE WHEN bo.sellers_sharing_buyer >= 2 THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS buyer_overlap_pct,
        COUNT(CASE WHEN bo.sellers_sharing_buyer >= 2 THEN 1 END)
                                                            AS shared_buyers_count
    FROM buyer_overlap bo
    GROUP BY bo.cluster_id
),

-- Step 6: Measure listing synchronization within each cluster
listing_sync AS (
    SELECT
        ca.cluster_id,
        nl.listing_created_at,
        ca.seller_id,
        COUNT(*) OVER (
            PARTITION BY ca.cluster_id
            ORDER BY nl.listing_created_at
            RANGE BETWEEN INTERVAL '30 MINUTES' PRECEDING AND INTERVAL '30 MINUTES' FOLLOWING
        )                                                   AS nearby_listings_count
    FROM cluster_assignment ca
    INNER JOIN normalized_listings nl
        ON ca.seller_id = nl.seller_id
        AND nl.listing_created_at >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

listing_sync_rate AS (
    SELECT
        cluster_id,
        ROUND(100.0 * COUNT(CASE WHEN nearby_listings_count >= 2 THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS sync_listing_rate_pct
    FROM listing_sync
    GROUP BY cluster_id
),

-- Step 7: Score and flag clusters
flagged_clusters AS (
    SELECT
        cm.*,
        bor.buyer_overlap_pct,
        bor.shared_buyers_count,
        lsr.sync_listing_rate_pct,
        CASE
            WHEN cm.cluster_size >= 5
             AND bor.buyer_overlap_pct >= 40
             AND lsr.sync_listing_rate_pct >= 30            THEN 'HIGH — Large Coordinated Ring'
            WHEN cm.cluster_size >= (SELECT min_cluster_size FROM thresholds)
             AND bor.buyer_overlap_pct >= (SELECT min_buyer_overlap_pct FROM thresholds)
                                                            THEN 'HIGH — Shared Buyers + Infrastructure'
            WHEN cm.cluster_size >= (SELECT min_cluster_size FROM thresholds)
             AND lsr.sync_listing_rate_pct >= 25            THEN 'MEDIUM — Synchronized Listing Behavior'
            WHEN cm.cluster_size >= (SELECT min_cluster_size FROM thresholds)
                                                            THEN 'MEDIUM — Infrastructure Overlap Only'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM cluster_metrics cm
    LEFT JOIN buyer_overlap_rate bor
        ON cm.cluster_id = bor.cluster_id
    LEFT JOIN listing_sync_rate lsr
        ON cm.cluster_id = lsr.cluster_id
    CROSS JOIN thresholds t
    WHERE cm.cluster_size >= t.min_cluster_size
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    cluster_id,
    cluster_size,
    cluster_members,
    total_listings,
    total_gmv,
    total_transactions,
    distinct_buyers,
    buyer_overlap_pct,
    shared_buyers_count,
    sync_listing_rate_pct,
    earliest_registration,
    latest_registration,
    registration_span_days,

    signal_confidence,
    'Seller Collusion Rings'                                AS signal_name,
    'Cluster of ' || cluster_size::VARCHAR
        || ' sellers sharing infrastructure (cluster root: '
        || cluster_id::VARCHAR || '). Combined GMV: $'
        || ROUND(total_gmv, 0)::VARCHAR
        || ' across ' || total_transactions::VARCHAR || ' transactions. '
        || buyer_overlap_pct::VARCHAR || '% buyer overlap ('
        || shared_buyers_count::VARCHAR || ' shared buyers). '
        || sync_listing_rate_pct::VARCHAR
        || '% of listings created within synchronized windows. '
        || 'Registration span: ' || registration_span_days::VARCHAR
        || ' days.'                                         AS glass_box_verdict

FROM flagged_clusters
ORDER BY signal_confidence, total_gmv DESC;

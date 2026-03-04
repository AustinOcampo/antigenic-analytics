-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: FAKE LISTING VELOCITY
-- =============================================================================
-- File:     fake_listing_velocity_detection.sql
-- Signal:   M02 of 10 — Marketplace & Platform Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Seller accounts creating listings at volumes that suggest automated or
-- templated generation rather than legitimate inventory management. Fake
-- listings are used to flood search results, test platform controls,
-- manipulate category rankings, or create storefronts for triangulation fraud.
-- The velocity pattern — not just the volume — distinguishes bulk fraud
-- from legitimate high-volume sellers.
--
-- BEHAVIORAL TELL:
-- Legitimate high-volume sellers ramp gradually. Their listings have variable
-- descriptions, unique photography, and staggered creation times. Fake listing
-- operations show burst creation — dozens of listings within minutes — with
-- templated titles, recycled images (same file hash), and prices clustered
-- at strategic points. The ratio of listings created to listings that ever
-- receive a transaction is the strongest single indicator.
--
-- DATA REQUIREMENTS:
-- Requires: seller_id, listing_id, listing_created_at, listing_title,
--           listing_price, listing_status
-- Optional: listing_image_hash, listing_description_length, listing_category,
--           transaction_id, transaction_timestamp
--
-- TUNING PARAMETERS:
-- * burst_window_minutes     — time window to measure burst creation (default: 60)
-- * burst_threshold          — listings in one burst to flag (default: 10)
-- * min_listings             — minimum total listings before analysis (default: 15)
-- * max_conversion_rate_pct  — listings with 0 sales above this % is suspicious (default: 80)
-- * lookback_days            — analysis window (default: 90)
--
-- TYPICAL EXPOSURE: $25K–$500K in platform integrity damage
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- This is the only section you edit.
-- =============================================================================

WITH normalized_listings AS (

    SELECT
        listing_id              AS listing_id,               -- expected: VARCHAR / STRING
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        created_at              AS listing_created_at,        -- expected: TIMESTAMP_NTZ
        title                   AS listing_title,            -- expected: VARCHAR
        price                   AS listing_price,            -- expected: FLOAT / NUMBER
        status                  AS listing_status,           -- expected: VARCHAR ('active','sold','removed','expired')
        image_hash              AS listing_image_hash,       -- expected: VARCHAR (NULL if not tracked)
        LENGTH(description)     AS listing_description_length, -- expected: INTEGER
        category                AS listing_category,         -- expected: VARCHAR

    FROM your_listing_table                                  -- << REPLACE WITH YOUR TABLE

),

normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,           -- expected: VARCHAR / STRING
        listing_id              AS listing_id,               -- expected: VARCHAR / STRING
        created_at              AS transaction_timestamp,     -- expected: TIMESTAMP_NTZ

    FROM your_transaction_table                              -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        60      AS burst_window_minutes,        -- 10+ listings in 60 min = automated behavior
        10      AS burst_threshold,             -- organic sellers rarely create 10 listings in an hour
        15      AS min_listings,                -- need enough volume to establish a pattern
        80.0    AS max_conversion_rate_pct,     -- if 80%+ of listings never sell, they exist for another purpose
        90      AS lookback_days                -- 3 months captures campaign-style listing fraud
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

-- Step 1: Filter to analysis window
listings_in_scope AS (
    SELECT *
    FROM normalized_listings
    WHERE listing_created_at >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 2: Count burst creation events per seller
listing_bursts AS (
    SELECT
        seller_id,
        listing_created_at,
        COUNT(*) OVER (
            PARTITION BY seller_id
            ORDER BY listing_created_at
            RANGE BETWEEN INTERVAL '60 MINUTES' PRECEDING AND CURRENT ROW
        )                                                   AS listings_in_window
    FROM listings_in_scope
),

burst_summary AS (
    SELECT
        seller_id,
        COUNT(CASE WHEN listings_in_window >= (SELECT burst_threshold FROM thresholds)
              THEN 1 END)                                   AS burst_events,
        MAX(listings_in_window)                              AS max_burst_size,
        MIN(CASE WHEN listings_in_window >= (SELECT burst_threshold FROM thresholds)
            THEN listing_created_at END)                    AS first_burst_at,
        MAX(CASE WHEN listings_in_window >= (SELECT burst_threshold FROM thresholds)
            THEN listing_created_at END)                    AS last_burst_at
    FROM listing_bursts
    GROUP BY seller_id
),

-- Step 3: Compute seller-level listing metrics
seller_listing_stats AS (
    SELECT
        l.seller_id,
        COUNT(DISTINCT l.listing_id)                        AS total_listings,
        COUNT(DISTINCT t.transaction_id)                    AS listings_with_sales,
        ROUND(100.0 * (COUNT(DISTINCT l.listing_id) - COUNT(DISTINCT t.listing_id))
            / NULLIF(COUNT(DISTINCT l.listing_id), 0), 1)  AS zero_sale_rate_pct,
        COUNT(DISTINCT l.listing_image_hash)                AS distinct_images,
        ROUND(100.0 * COUNT(DISTINCT l.listing_image_hash)
            / NULLIF(COUNT(DISTINCT l.listing_id), 0), 1)  AS image_uniqueness_pct,
        AVG(l.listing_description_length)                   AS avg_description_length,
        STDDEV(l.listing_description_length)                AS stddev_description_length,
        COUNT(DISTINCT l.listing_category)                  AS categories_listed,
        MIN(l.listing_created_at)                           AS first_listing,
        MAX(l.listing_created_at)                           AS last_listing,
        DATEDIFF('day', MIN(l.listing_created_at),
                 MAX(l.listing_created_at))                 AS active_span_days,
        -- Price clustering: low std dev relative to mean = templated pricing
        ROUND(STDDEV(l.listing_price)
            / NULLIF(AVG(l.listing_price), 0) * 100, 1)    AS price_variation_cv_pct
    FROM listings_in_scope l
    LEFT JOIN normalized_transactions t
        ON l.listing_id = t.listing_id
    GROUP BY l.seller_id
),

-- Step 4: Score and flag
flagged_sellers AS (
    SELECT
        sls.*,
        bs.burst_events,
        bs.max_burst_size,
        bs.first_burst_at,
        bs.last_burst_at,
        CASE
            WHEN bs.burst_events >= 3
             AND sls.zero_sale_rate_pct >= 90
             AND sls.image_uniqueness_pct <= 30             THEN 'HIGH — Automated Listing Farm'
            WHEN bs.burst_events >= 1
             AND sls.zero_sale_rate_pct >= (SELECT max_conversion_rate_pct FROM thresholds)
                                                            THEN 'HIGH — Burst Creation + No Sales'
            WHEN sls.zero_sale_rate_pct >= 90
             AND sls.total_listings >= 50                   THEN 'MEDIUM — High Volume Zero Conversion'
            WHEN bs.burst_events >= 1
             AND sls.price_variation_cv_pct <= 5            THEN 'MEDIUM — Burst + Templated Pricing'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM seller_listing_stats sls
    LEFT JOIN burst_summary bs
        ON sls.seller_id = bs.seller_id
    CROSS JOIN thresholds t
    WHERE sls.total_listings >= t.min_listings
      AND (
          bs.burst_events >= 1
          OR sls.zero_sale_rate_pct >= t.max_conversion_rate_pct
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    seller_id,
    total_listings,
    listings_with_sales,
    zero_sale_rate_pct,
    burst_events,
    max_burst_size,
    image_uniqueness_pct,
    avg_description_length,
    price_variation_cv_pct,
    categories_listed,
    active_span_days,

    signal_confidence,
    'Fake Listing Velocity'                                 AS signal_name,
    'Seller ' || seller_id
        || ' created ' || total_listings::VARCHAR || ' listings in '
        || active_span_days::VARCHAR || ' days. '
        || zero_sale_rate_pct::VARCHAR || '% have zero sales. '
        || COALESCE(burst_events::VARCHAR || ' burst creation events detected (max '
           || max_burst_size::VARCHAR || ' listings in 60 min). ', '')
        || 'Image uniqueness: ' || image_uniqueness_pct::VARCHAR || '%. '
        || 'Price variation CV: ' || price_variation_cv_pct::VARCHAR
        || '%.'                                             AS glass_box_verdict

FROM flagged_sellers
ORDER BY signal_confidence, total_listings DESC;

-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: REVIEW FRAUD CLUSTERING
-- =============================================================================
-- File:     review_fraud_clustering_detection.sql
-- Signal:   M04 of 10 — Marketplace & Platform Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Clusters of reviews tied to the same devices, IPs, or behavioral fingerprints
-- that artificially inflate seller ratings or suppress competitors. Review fraud
-- operations leave infrastructure trails — shared devices, similar review timing,
-- identical rating patterns — that organic reviewers never produce.
--
-- BEHAVIORAL TELL:
-- Organic reviews arrive irregularly, vary in length, and reflect genuine
-- purchase experiences. Fraudulent review clusters show temporal bursts (many
-- reviews within hours), uniform ratings (all 5-star or all 1-star), short
-- or templated text, and reviewers who only review sellers within the same
-- collusion ring. The reviewer accounts themselves are often recently created
-- with minimal platform history.
--
-- DATA REQUIREMENTS:
-- Requires: review_id, reviewer_id, seller_id, listing_id, review_rating,
--           review_timestamp, reviewer_ip_address, reviewer_device_id
-- Optional: review_text_length, reviewer_account_created_at,
--           reviewer_total_reviews, reviewer_total_purchases, transaction_id
--
-- TUNING PARAMETERS:
-- * burst_window_hours       — time window for review burst detection (default: 24)
-- * burst_threshold          — reviews in one burst to flag (default: 5)
-- * min_reviews_to_flag      — minimum reviews on seller before analysis (default: 10)
-- * new_reviewer_days        — reviewer account age below which is suspicious (default: 30)
-- * new_reviewer_pct_threshold — % of reviews from new accounts to flag (default: 50%)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $20K–$300K in marketplace integrity damage
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_reviews AS (

    SELECT
        review_id               AS review_id,                -- expected: VARCHAR / STRING
        reviewer_id             AS reviewer_id,              -- expected: VARCHAR / STRING
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        listing_id              AS listing_id,               -- expected: VARCHAR / STRING
        rating                  AS review_rating,            -- expected: INTEGER (1-5)
        created_at              AS review_timestamp,         -- expected: TIMESTAMP_NTZ
        ip_address              AS reviewer_ip_address,      -- expected: VARCHAR
        device_id               AS reviewer_device_id,       -- expected: VARCHAR
        LENGTH(review_text)     AS review_text_length,       -- expected: INTEGER

    FROM your_review_table                                   -- << REPLACE WITH YOUR TABLE

),

normalized_reviewers AS (

    SELECT
        reviewer_id             AS reviewer_id,              -- expected: VARCHAR / STRING
        created_at              AS reviewer_account_created_at, -- expected: TIMESTAMP_NTZ
        total_reviews           AS reviewer_total_reviews,   -- expected: INTEGER
        total_purchases         AS reviewer_total_purchases, -- expected: INTEGER

    FROM your_user_table                                     -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        24      AS burst_window_hours,          -- 5+ reviews in 24 hrs on same seller = coordinated
        5       AS burst_threshold,             -- organic sellers rarely get 5 reviews in a day
        10      AS min_reviews_to_flag,         -- need statistical basis before flagging
        30      AS new_reviewer_days,           -- reviewer accounts < 30 days old are suspicious sources
        50.0    AS new_reviewer_pct_threshold,  -- if 50%+ of reviews come from new accounts = inorganic
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

reviews_in_scope AS (
    SELECT *
    FROM normalized_reviews
    WHERE review_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 1: Detect review bursts per seller
review_bursts AS (
    SELECT
        seller_id,
        review_timestamp,
        reviewer_id,
        COUNT(*) OVER (
            PARTITION BY seller_id
            ORDER BY review_timestamp
            RANGE BETWEEN INTERVAL '24 HOURS' PRECEDING AND CURRENT ROW
        )                                                   AS reviews_in_window
    FROM reviews_in_scope
),

burst_summary AS (
    SELECT
        seller_id,
        COUNT(CASE WHEN reviews_in_window >= (SELECT burst_threshold FROM thresholds)
              THEN 1 END)                                   AS burst_events,
        MAX(reviews_in_window)                              AS max_burst_size
    FROM review_bursts
    GROUP BY seller_id
),

-- Step 2: Detect shared infrastructure among reviewers for each seller
reviewer_infra_per_seller AS (
    SELECT
        r.seller_id,
        r.reviewer_ip_address,
        r.reviewer_device_id,
        COUNT(DISTINCT r.reviewer_id)                       AS reviewers_sharing_infra
    FROM reviews_in_scope r
    WHERE r.reviewer_ip_address IS NOT NULL
       OR r.reviewer_device_id IS NOT NULL
    GROUP BY r.seller_id, r.reviewer_ip_address, r.reviewer_device_id
    HAVING COUNT(DISTINCT r.reviewer_id) >= 2
),

shared_infra_summary AS (
    SELECT
        seller_id,
        SUM(reviewers_sharing_infra)                        AS total_shared_infra_reviews,
        COUNT(*)                                            AS distinct_shared_infra_clusters
    FROM reviewer_infra_per_seller
    GROUP BY seller_id
),

-- Step 3: Analyze reviewer account age and activity
reviewer_quality AS (
    SELECT
        r.seller_id,
        COUNT(DISTINCT r.review_id)                         AS total_reviews,
        COUNT(DISTINCT r.reviewer_id)                       AS distinct_reviewers,
        AVG(r.review_rating)                                AS avg_rating,
        STDDEV(r.review_rating)                             AS stddev_rating,
        AVG(r.review_text_length)                           AS avg_text_length,
        -- New reviewer percentage
        ROUND(100.0 * COUNT(CASE
            WHEN DATEDIFF('day', nr.reviewer_account_created_at, r.review_timestamp)
                 <= (SELECT new_reviewer_days FROM thresholds)
            THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS new_reviewer_pct,
        -- Single-review reviewer percentage
        ROUND(100.0 * COUNT(CASE
            WHEN nr.reviewer_total_reviews <= 1
            THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS single_review_pct,
        -- Rating uniformity (all same rating)
        ROUND(100.0 * COUNT(CASE WHEN r.review_rating = 5 THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS five_star_pct
    FROM reviews_in_scope r
    LEFT JOIN normalized_reviewers nr
        ON r.reviewer_id = nr.reviewer_id
    GROUP BY r.seller_id
),

-- Step 4: Score and flag
flagged_sellers AS (
    SELECT
        rq.*,
        COALESCE(bs.burst_events, 0)                        AS burst_events,
        COALESCE(bs.max_burst_size, 0)                      AS max_burst_size,
        COALESCE(sis.total_shared_infra_reviews, 0)         AS shared_infra_reviews,
        COALESCE(sis.distinct_shared_infra_clusters, 0)     AS shared_infra_clusters,
        CASE
            WHEN COALESCE(sis.distinct_shared_infra_clusters, 0) >= 3
             AND rq.new_reviewer_pct >= 60
             AND COALESCE(bs.burst_events, 0) >= 2          THEN 'HIGH — Coordinated Review Farm'
            WHEN COALESCE(sis.distinct_shared_infra_clusters, 0) >= 2
             AND rq.five_star_pct >= 90                     THEN 'HIGH — Shared Devices + Uniform Ratings'
            WHEN rq.new_reviewer_pct >= (SELECT new_reviewer_pct_threshold FROM thresholds)
             AND rq.single_review_pct >= 60                 THEN 'MEDIUM — Disposable Reviewer Accounts'
            WHEN COALESCE(bs.burst_events, 0) >= 1
             AND rq.stddev_rating <= 0.5                    THEN 'MEDIUM — Burst + Rating Uniformity'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM reviewer_quality rq
    LEFT JOIN burst_summary bs
        ON rq.seller_id = bs.seller_id
    LEFT JOIN shared_infra_summary sis
        ON rq.seller_id = sis.seller_id
    CROSS JOIN thresholds t
    WHERE rq.total_reviews >= t.min_reviews_to_flag
      AND (
          COALESCE(sis.distinct_shared_infra_clusters, 0) >= 2
          OR rq.new_reviewer_pct >= t.new_reviewer_pct_threshold
          OR COALESCE(bs.burst_events, 0) >= 1
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    seller_id,
    total_reviews,
    distinct_reviewers,
    avg_rating,
    five_star_pct,
    new_reviewer_pct,
    single_review_pct,
    burst_events,
    max_burst_size,
    shared_infra_reviews,
    shared_infra_clusters,
    avg_text_length,

    signal_confidence,
    'Review Fraud Clustering'                               AS signal_name,
    'Seller ' || seller_id
        || ' received ' || total_reviews::VARCHAR || ' reviews from '
        || distinct_reviewers::VARCHAR || ' reviewers. '
        || five_star_pct::VARCHAR || '% are 5-star. '
        || new_reviewer_pct::VARCHAR || '% from accounts < 30 days old. '
        || single_review_pct::VARCHAR || '% from single-review accounts. '
        || CASE WHEN shared_infra_clusters > 0
           THEN shared_infra_clusters::VARCHAR || ' shared device/IP clusters detected. '
           ELSE '' END
        || CASE WHEN burst_events > 0
           THEN burst_events::VARCHAR || ' review burst events (max '
                || max_burst_size::VARCHAR || ' in 24 hrs). '
           ELSE '' END
        || 'Avg review length: ' || ROUND(avg_text_length, 0)::VARCHAR
        || ' chars.'                                        AS glass_box_verdict

FROM flagged_sellers
ORDER BY signal_confidence, total_reviews DESC;

-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: ACCOUNT FLIPPING
-- =============================================================================
-- File:     account_flipping_detection.sql
-- Signal:   M06 of 10 — Marketplace & Platform Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Accounts created, built up with fake reputation, then sold or transferred
-- to bad actors. Account flipping operations show a distinct two-phase
-- behavioral pattern: a "building" phase with organic-looking activity
-- designed to establish trust metrics, followed by an abrupt behavioral
-- shift when the new operator takes over — different login locations,
-- different product categories, different transaction patterns.
--
-- BEHAVIORAL TELL:
-- Legitimate sellers evolve gradually. Their categories expand slowly, their
-- login patterns are geographically stable, and their pricing strategies
-- shift incrementally. Flipped accounts show a hard break: sudden category
-- changes, new IP addresses and devices, different listing cadences, and
-- often a spike in aggressive selling immediately after the behavioral shift
-- as the new operator monetizes the acquired reputation.
--
-- DATA REQUIREMENTS:
-- Requires: seller_id, login_timestamp, login_ip_address, login_device_id,
--           listing_id, listing_category, listing_created_at, transaction_id,
--           transaction_amount, transaction_timestamp
-- Optional: seller_registration_date, seller_email_change_date,
--           seller_password_change_date, seller_bank_change_date
--
-- TUNING PARAMETERS:
-- * behavioral_shift_window_days — window to compare before/after (default: 30)
-- * min_account_age_days         — minimum age before flip detection (default: 90)
-- * ip_change_threshold          — % new IPs in recent window to flag (default: 80%)
-- * category_shift_threshold     — % new categories in recent window (default: 60%)
-- * lookback_days                — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $30K–$500K per flipped account operation
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_logins AS (

    SELECT
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        login_at                AS login_timestamp,          -- expected: TIMESTAMP_NTZ
        ip_address              AS login_ip_address,         -- expected: VARCHAR
        device_id               AS login_device_id,          -- expected: VARCHAR

    FROM your_login_table                                    -- << REPLACE WITH YOUR TABLE

),

normalized_listings AS (

    SELECT
        listing_id              AS listing_id,               -- expected: VARCHAR / STRING
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        created_at              AS listing_created_at,        -- expected: TIMESTAMP_NTZ
        category                AS listing_category,         -- expected: VARCHAR

    FROM your_listing_table                                  -- << REPLACE WITH YOUR TABLE

),

normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,           -- expected: VARCHAR / STRING
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        amount                  AS transaction_amount,        -- expected: FLOAT / NUMBER
        created_at              AS transaction_timestamp,     -- expected: TIMESTAMP_NTZ

    FROM your_transaction_table                              -- << REPLACE WITH YOUR TABLE

),

normalized_sellers AS (

    SELECT
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        created_at              AS seller_registration_date,  -- expected: TIMESTAMP_NTZ
        email_changed_at        AS seller_email_change_date,  -- expected: TIMESTAMP_NTZ (NULL if never)
        password_changed_at     AS seller_password_change_date, -- expected: TIMESTAMP_NTZ (NULL if never)
        bank_changed_at         AS seller_bank_change_date,   -- expected: TIMESTAMP_NTZ (NULL if never)

    FROM your_seller_table                                   -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        30      AS behavioral_shift_window_days, -- compare last 30 days vs prior period
        90      AS min_account_age_days,         -- accounts < 90 days don't have enough baseline
        80.0    AS ip_change_threshold,          -- 80%+ new IPs in recent window = different operator
        60.0    AS category_shift_threshold,     -- 60%+ new categories = different business
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

-- Step 1: Split login history into recent vs. historical
login_comparison AS (
    SELECT
        seller_id,
        login_ip_address,
        login_device_id,
        CASE
            WHEN login_timestamp >= DATEADD('day', -1 * (SELECT behavioral_shift_window_days FROM thresholds), CURRENT_TIMESTAMP())
            THEN 'RECENT' ELSE 'HISTORICAL'
        END                                                 AS period
    FROM normalized_logins
    WHERE login_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 2: Measure IP and device continuity
ip_continuity AS (
    SELECT
        r.seller_id,
        COUNT(DISTINCT r.login_ip_address)                  AS recent_distinct_ips,
        COUNT(DISTINCT h.login_ip_address)                  AS historical_distinct_ips,
        COUNT(DISTINCT CASE
            WHEN r.login_ip_address NOT IN (
                SELECT DISTINCT login_ip_address FROM login_comparison
                WHERE seller_id = r.seller_id AND period = 'HISTORICAL'
            ) THEN r.login_ip_address END)                  AS new_ips_in_recent
    FROM login_comparison r
    LEFT JOIN login_comparison h
        ON r.seller_id = h.seller_id AND h.period = 'HISTORICAL'
    WHERE r.period = 'RECENT'
    GROUP BY r.seller_id
),

ip_shift AS (
    SELECT
        seller_id,
        recent_distinct_ips,
        historical_distinct_ips,
        new_ips_in_recent,
        ROUND(100.0 * new_ips_in_recent
            / NULLIF(recent_distinct_ips, 0), 1)            AS new_ip_pct
    FROM ip_continuity
),

-- Step 3: Measure category continuity
category_comparison AS (
    SELECT
        seller_id,
        listing_category,
        CASE
            WHEN listing_created_at >= DATEADD('day', -1 * (SELECT behavioral_shift_window_days FROM thresholds), CURRENT_TIMESTAMP())
            THEN 'RECENT' ELSE 'HISTORICAL'
        END                                                 AS period
    FROM normalized_listings
    WHERE listing_created_at >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

category_shift AS (
    SELECT
        seller_id,
        COUNT(DISTINCT CASE WHEN period = 'RECENT' THEN listing_category END)
                                                            AS recent_categories,
        COUNT(DISTINCT CASE WHEN period = 'HISTORICAL' THEN listing_category END)
                                                            AS historical_categories,
        COUNT(DISTINCT CASE
            WHEN period = 'RECENT' AND listing_category NOT IN (
                SELECT DISTINCT listing_category FROM category_comparison cc2
                WHERE cc2.seller_id = category_comparison.seller_id AND cc2.period = 'HISTORICAL'
            ) THEN listing_category END)                    AS new_categories_in_recent
    FROM category_comparison
    GROUP BY seller_id
),

category_shift_pct AS (
    SELECT
        seller_id,
        recent_categories,
        historical_categories,
        new_categories_in_recent,
        ROUND(100.0 * new_categories_in_recent
            / NULLIF(recent_categories, 0), 1)              AS new_category_pct
    FROM category_shift
),

-- Step 4: Detect credential changes (email, password, bank)
credential_changes AS (
    SELECT
        seller_id,
        seller_registration_date,
        DATEDIFF('day', seller_registration_date, CURRENT_TIMESTAMP())
                                                            AS account_age_days,
        seller_email_change_date,
        seller_password_change_date,
        seller_bank_change_date,
        -- Count recent credential changes
        (CASE WHEN seller_email_change_date >= DATEADD('day', -1 * (SELECT behavioral_shift_window_days FROM thresholds), CURRENT_TIMESTAMP()) THEN 1 ELSE 0 END
       + CASE WHEN seller_password_change_date >= DATEADD('day', -1 * (SELECT behavioral_shift_window_days FROM thresholds), CURRENT_TIMESTAMP()) THEN 1 ELSE 0 END
       + CASE WHEN seller_bank_change_date >= DATEADD('day', -1 * (SELECT behavioral_shift_window_days FROM thresholds), CURRENT_TIMESTAMP()) THEN 1 ELSE 0 END
        )                                                   AS recent_credential_changes
    FROM normalized_sellers
),

-- Step 5: Transaction velocity shift
txn_velocity AS (
    SELECT
        seller_id,
        SUM(CASE WHEN transaction_timestamp >= DATEADD('day', -1 * (SELECT behavioral_shift_window_days FROM thresholds), CURRENT_TIMESTAMP())
            THEN transaction_amount ELSE 0 END)             AS recent_gmv,
        SUM(CASE WHEN transaction_timestamp < DATEADD('day', -1 * (SELECT behavioral_shift_window_days FROM thresholds), CURRENT_TIMESTAMP())
            THEN transaction_amount ELSE 0 END)             AS historical_gmv,
        COUNT(CASE WHEN transaction_timestamp >= DATEADD('day', -1 * (SELECT behavioral_shift_window_days FROM thresholds), CURRENT_TIMESTAMP())
              THEN 1 END)                                   AS recent_txn_count,
        COUNT(CASE WHEN transaction_timestamp < DATEADD('day', -1 * (SELECT behavioral_shift_window_days FROM thresholds), CURRENT_TIMESTAMP())
              THEN 1 END)                                   AS historical_txn_count
    FROM normalized_transactions
    WHERE transaction_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
    GROUP BY seller_id
),

-- Step 6: Score and flag
flagged_sellers AS (
    SELECT
        cc.seller_id,
        cc.account_age_days,
        cc.recent_credential_changes,
        ips.new_ip_pct,
        ips.recent_distinct_ips,
        csp.new_category_pct,
        csp.recent_categories,
        csp.historical_categories,
        tv.recent_gmv,
        tv.historical_gmv,
        tv.recent_txn_count,
        tv.historical_txn_count,
        CASE
            WHEN ips.new_ip_pct >= 80
             AND csp.new_category_pct >= 60
             AND cc.recent_credential_changes >= 2          THEN 'HIGH — Full Account Takeover Pattern'
            WHEN ips.new_ip_pct >= (SELECT ip_change_threshold FROM thresholds)
             AND csp.new_category_pct >= (SELECT category_shift_threshold FROM thresholds)
                                                            THEN 'HIGH — Infrastructure + Category Shift'
            WHEN ips.new_ip_pct >= (SELECT ip_change_threshold FROM thresholds)
             AND cc.recent_credential_changes >= 1          THEN 'MEDIUM — New Infrastructure + Credential Change'
            WHEN csp.new_category_pct >= (SELECT category_shift_threshold FROM thresholds)
             AND tv.recent_gmv > tv.historical_gmv * 3      THEN 'MEDIUM — Category Shift + GMV Spike'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM credential_changes cc
    LEFT JOIN ip_shift ips ON cc.seller_id = ips.seller_id
    LEFT JOIN category_shift_pct csp ON cc.seller_id = csp.seller_id
    LEFT JOIN txn_velocity tv ON cc.seller_id = tv.seller_id
    CROSS JOIN thresholds t
    WHERE cc.account_age_days >= t.min_account_age_days
      AND (
          ips.new_ip_pct >= t.ip_change_threshold
          OR csp.new_category_pct >= t.category_shift_threshold
          OR cc.recent_credential_changes >= 2
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    seller_id,
    account_age_days,
    new_ip_pct,
    recent_distinct_ips,
    new_category_pct,
    recent_categories,
    historical_categories,
    recent_credential_changes,
    recent_gmv,
    historical_gmv,
    recent_txn_count,

    signal_confidence,
    'Account Flipping'                                      AS signal_name,
    'Seller ' || seller_id
        || ' (account age: ' || account_age_days::VARCHAR || ' days) shows '
        || 'behavioral discontinuity. '
        || new_ip_pct::VARCHAR || '% new IPs in last 30 days. '
        || new_category_pct::VARCHAR || '% new listing categories. '
        || CASE WHEN recent_credential_changes > 0
           THEN recent_credential_changes::VARCHAR || ' credential changes (email/password/bank). '
           ELSE '' END
        || 'Recent GMV: $' || ROUND(recent_gmv, 0)::VARCHAR
        || ' vs prior: $' || ROUND(historical_gmv, 0)::VARCHAR
        || '.'                                              AS glass_box_verdict

FROM flagged_sellers
ORDER BY signal_confidence, recent_gmv DESC;

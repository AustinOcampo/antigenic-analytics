-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: COUPON NETWORK DISTRIBUTION
-- =============================================================================
-- File:     coupon_network_distribution_detection.sql
-- Signal:   L13 of 13 — Loyalty, Rewards & Promotion Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Single-use or limited-use coupon codes that appear across far more accounts
-- than their intended distribution would allow. This indicates coupon codes
-- are being leaked, shared on forums, or systematically harvested and
-- redistributed. The signal traces redemption patterns back to distribution
-- networks — groups of accounts that consistently redeem the same codes,
-- suggesting a common source feeding them promotional offers.
--
-- BEHAVIORAL TELL:
-- Legitimate coupon distribution produces a predictable redemption curve:
-- codes are redeemed by the intended audience, usage peaks near the
-- distribution event, and redemption sources (device, IP, geography) are
-- diverse. Leaked or networked codes show abnormal redemption velocity
-- (sudden spikes from unexpected sources), geographic clustering that
-- doesn't match the campaign target, and code-to-account ratios that
-- exceed the distribution channel's reach. The same codes appear across
-- accounts that share behavioral fingerprints, revealing the distribution
-- network.
--
-- DATA REQUIREMENTS:
-- Requires: promo_code, member_id, redemption_timestamp, discount_amount,
--           transaction_id
-- Optional: promo_code_campaign, promo_code_channel, intended_recipient_count,
--           member_device_id, member_ip_address, member_city
--
-- TUNING PARAMETERS:
-- * redemption_multiplier    — redemptions vs intended recipients to flag (default: 3x)
-- * min_redemptions          — minimum redemptions of a code to analyze (default: 10)
-- * geographic_concentration — % of redemptions from a single city to flag (default: 50%)
-- * velocity_spike_threshold — redemptions per hour above which to flag (default: 20)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $10,000 — $200,000
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_redemptions AS (

    SELECT
        promo_code              AS promo_code,               -- expected: VARCHAR
        member_id               AS member_id,                -- expected: VARCHAR
        redeemed_at             AS redemption_timestamp,     -- expected: TIMESTAMP_NTZ
        discount_amount         AS discount_amount,          -- expected: FLOAT
        transaction_id          AS transaction_id,           -- expected: VARCHAR
        device_id               AS member_device_id,         -- expected: VARCHAR (NULL if not tracked)
        ip_address              AS member_ip_address,        -- expected: VARCHAR (NULL if not tracked)
        city                    AS member_city,              -- expected: VARCHAR (NULL if not geolocated)

    FROM your_redemption_table                               -- << REPLACE WITH YOUR TABLE

    WHERE redeemed_at >= DATEADD('day', -180, CURRENT_TIMESTAMP())  -- << ADJUST LOOKBACK

),

-- If you track campaign metadata for promo codes, map here
normalized_campaigns AS (

    SELECT
        promo_code              AS promo_code,               -- expected: VARCHAR
        campaign_name           AS campaign_name,            -- expected: VARCHAR
        distribution_channel    AS distribution_channel,     -- expected: VARCHAR ('email','social','influencer','internal')
        intended_recipients     AS intended_recipient_count, -- expected: INTEGER
        launched_at             AS campaign_launch_date,     -- expected: TIMESTAMP_NTZ
        expires_at              AS campaign_expiry_date,     -- expected: TIMESTAMP_NTZ

    FROM your_campaign_table                                 -- << REPLACE WITH YOUR TABLE (or use empty CTE)

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        3.0     AS redemption_multiplier,       -- 3x more redemptions than intended = leaked
        10      AS min_redemptions,             -- need enough volume to distinguish leak from organic sharing
        50.0    AS geographic_concentration,    -- 50%+ of redemptions from one city = targeted distribution
        20      AS velocity_spike_threshold,    -- 20+ redemptions per hour = forum post or bulk distribution
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

-- Step 1: Code-level redemption statistics
code_stats AS (
    SELECT
        r.promo_code,
        COUNT(DISTINCT r.transaction_id)                    AS total_redemptions,
        COUNT(DISTINCT r.member_id)                         AS distinct_redeemers,
        SUM(r.discount_amount)                              AS total_discount_value,
        AVG(r.discount_amount)                              AS avg_discount_per_use,
        MIN(r.redemption_timestamp)                         AS first_redemption,
        MAX(r.redemption_timestamp)                         AS last_redemption,
        DATEDIFF('hour', MIN(r.redemption_timestamp),
                 MAX(r.redemption_timestamp))               AS redemption_span_hours,
        -- Geographic analysis
        COUNT(DISTINCT r.member_city)                       AS distinct_cities,
        MODE(r.member_city)                                 AS top_city,
        ROUND(100.0 * COUNT(CASE WHEN r.member_city = MODE(r.member_city) THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS top_city_pct,
        -- Infrastructure analysis
        COUNT(DISTINCT r.member_device_id)                  AS distinct_devices,
        COUNT(DISTINCT r.member_ip_address)                 AS distinct_ips,
        -- Campaign metadata
        MAX(c.campaign_name)                                AS campaign_name,
        MAX(c.distribution_channel)                         AS distribution_channel,
        MAX(c.intended_recipient_count)                     AS intended_recipients,
        MAX(c.campaign_launch_date)                         AS campaign_launch_date
    FROM normalized_redemptions r
    LEFT JOIN normalized_campaigns c
        ON r.promo_code = c.promo_code
    GROUP BY r.promo_code
),

-- Step 2: Compute redemption-to-intended ratio
code_overage AS (
    SELECT
        cs.*,
        CASE
            WHEN cs.intended_recipients IS NOT NULL AND cs.intended_recipients > 0
            THEN ROUND(1.0 * cs.total_redemptions / cs.intended_recipients, 2)
            ELSE NULL
        END                                                 AS redemption_ratio,
        ROUND(1.0 * cs.total_redemptions
            / NULLIF(cs.redemption_span_hours, 0), 1)       AS avg_redemptions_per_hour
    FROM code_stats cs
),

-- Step 3: Detect velocity spikes (burst redemption events)
hourly_redemptions AS (
    SELECT
        promo_code,
        DATE_TRUNC('hour', redemption_timestamp)            AS redemption_hour,
        COUNT(*)                                            AS hourly_count
    FROM normalized_redemptions
    GROUP BY promo_code, DATE_TRUNC('hour', redemption_timestamp)
),

velocity_spikes AS (
    SELECT
        promo_code,
        MAX(hourly_count)                                   AS max_hourly_redemptions,
        COUNT(CASE WHEN hourly_count >= (SELECT velocity_spike_threshold FROM thresholds)
              THEN 1 END)                                   AS spike_hours
    FROM hourly_redemptions
    GROUP BY promo_code
),

-- Step 4: Detect redeemer networks (members who share codes)
-- Members who redeem 3+ of the same codes form a network
member_code_overlap AS (
    SELECT
        a.member_id             AS member_a,
        b.member_id             AS member_b,
        COUNT(DISTINCT a.promo_code)                        AS shared_codes
    FROM normalized_redemptions a
    INNER JOIN normalized_redemptions b
        ON a.promo_code = b.promo_code
        AND a.member_id < b.member_id
    GROUP BY a.member_id, b.member_id
    HAVING COUNT(DISTINCT a.promo_code) >= 3
),

network_summary AS (
    SELECT
        promo_code,
        COUNT(DISTINCT member_id)                           AS network_members
    FROM normalized_redemptions
    WHERE member_id IN (
        SELECT member_a FROM member_code_overlap
        UNION
        SELECT member_b FROM member_code_overlap
    )
    GROUP BY promo_code
),

-- Step 5: Score and flag
flagged_codes AS (
    SELECT
        co.*,
        COALESCE(vs.max_hourly_redemptions, 0)              AS max_hourly_redemptions,
        COALESCE(vs.spike_hours, 0)                         AS spike_hours,
        COALESCE(ns.network_members, 0)                     AS network_members,
        CASE
            WHEN co.redemption_ratio >= 5
             AND vs.spike_hours >= 2
             AND COALESCE(ns.network_members, 0) >= 10       THEN 'HIGH — Mass Leak + Distribution Network'
            WHEN co.redemption_ratio >= (SELECT redemption_multiplier FROM thresholds)
             AND vs.max_hourly_redemptions >= (SELECT velocity_spike_threshold FROM thresholds)
                                                            THEN 'HIGH — Over-Redemption + Velocity Spike'
            WHEN co.redemption_ratio >= (SELECT redemption_multiplier FROM thresholds)
             AND co.top_city_pct >= (SELECT geographic_concentration FROM thresholds)
                                                            THEN 'MEDIUM — Over-Redemption + Geographic Cluster'
            WHEN vs.max_hourly_redemptions >= (SELECT velocity_spike_threshold FROM thresholds) * 2
                                                            THEN 'MEDIUM — Extreme Velocity Spike'
            WHEN co.total_redemptions >= 50
             AND co.redemption_ratio IS NULL                 THEN 'MEDIUM — High Volume (No Campaign Baseline)'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM code_overage co
    LEFT JOIN velocity_spikes vs
        ON co.promo_code = vs.promo_code
    LEFT JOIN network_summary ns
        ON co.promo_code = ns.promo_code
    CROSS JOIN thresholds t
    WHERE co.total_redemptions >= t.min_redemptions
      AND (
          co.redemption_ratio >= t.redemption_multiplier
          OR COALESCE(vs.max_hourly_redemptions, 0) >= t.velocity_spike_threshold
          OR co.top_city_pct >= t.geographic_concentration
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    promo_code,
    campaign_name,
    distribution_channel,
    total_redemptions,
    intended_recipients,
    redemption_ratio,
    total_discount_value,
    distinct_redeemers,
    distinct_cities,
    top_city,
    top_city_pct,
    max_hourly_redemptions,
    spike_hours,
    network_members,
    redemption_span_hours,

    signal_confidence,
    'Coupon Network Distribution'                           AS signal_name,
    'Code "' || promo_code || '"'
        || CASE WHEN campaign_name IS NOT NULL
           THEN ' (' || campaign_name || ')' ELSE '' END
        || ': ' || total_redemptions::VARCHAR || ' redemptions'
        || CASE WHEN intended_recipients IS NOT NULL
           THEN ' vs ' || intended_recipients::VARCHAR || ' intended ('
                || redemption_ratio::VARCHAR || 'x over)'
           ELSE '' END
        || '. $' || ROUND(total_discount_value, 0)::VARCHAR || ' total discount. '
        || distinct_redeemers::VARCHAR || ' unique redeemers across '
        || distinct_cities::VARCHAR || ' cities. '
        || CASE WHEN top_city_pct >= 50
           THEN top_city_pct::VARCHAR || '% from ' || COALESCE(top_city, 'unknown') || '. '
           ELSE '' END
        || CASE WHEN max_hourly_redemptions >= 20
           THEN 'Peak: ' || max_hourly_redemptions::VARCHAR || ' redemptions/hr. '
           ELSE '' END
        || CASE WHEN network_members > 0
           THEN network_members::VARCHAR || ' members in shared-code network.'
           ELSE '' END                                      AS glass_box_verdict

FROM flagged_codes
ORDER BY signal_confidence, total_discount_value DESC;

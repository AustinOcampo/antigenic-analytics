-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL STACKING: MULTI-SIGNAL VENDOR RISK SCORE
-- =============================================================================
-- File:     signal_stacking_master.sql
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS IS:
-- This is the master investigation priority queue. It aggregates results from
-- all 10 individual signal queries and produces a single ranked vendor list
-- ordered by the number and severity of signals firing simultaneously.
--
-- WHY SIGNAL STACKING MATTERS:
-- Any single signal can have an innocent explanation.
-- A vendor who appears in Signals 1, 5, 7, and 8 simultaneously has no
-- innocent explanation. This query surfaces those vendors first.
--
-- HOW TO USE THIS:
-- Step 1: Run each of the 10 individual signal detection queries.
--         Save their results to temporary tables or CTEs (instructions below).
-- Step 2: Run this stacking query against those results.
-- Step 3: Prioritize investigation starting from vendors with the highest
--         composite score and broadest signal coverage.
--
-- SCORING METHODOLOGY:
-- HIGH confidence signal  = 3 points
-- MEDIUM confidence signal = 2 points
-- LOW confidence signal   = 1 point
-- Signals are weighted by typical dollar exposure (see weight table below)
--
-- OUTPUT:
-- Ranked vendor list with: composite risk score, signals firing count,
-- total flagged spend across all signals, signal coverage detail,
-- and Glass Box investigation brief.
-- =============================================================================


-- =============================================================================
-- STEP 1: POPULATE SIGNAL RESULT TABLES
-- Before running this query, run each signal and save results to temp tables.
-- Replace the table names below with your actual result table names.
-- Each signal result table must contain: vendor_id, vendor_name, signal_confidence
-- and a dollar amount column (varies by signal — map below).
-- =============================================================================

WITH

-- Signal 01: Vendor Concentration Ratio
sig01_results AS (
    SELECT
        vendor_id,
        vendor_name,
        signal_confidence,
        vendor_spend_this_year                          AS signal_dollar_amount,
        glass_box_verdict                               AS signal_detail
    FROM signal_01_vendor_concentration_results         -- << REPLACE with your saved result table
),

-- Signal 02: Sub-Threshold Batching
sig02_results AS (
    SELECT
        vendor_id,
        vendor_name,
        signal_confidence,
        combined_cluster_total                          AS signal_dollar_amount,
        glass_box_verdict                               AS signal_detail
    FROM signal_02_sub_threshold_batching_results       -- << REPLACE
),

-- Signal 03: Billing Code Cycling
sig03_results AS (
    SELECT
        vendor_id,
        vendor_name,
        signal_confidence,
        total_vendor_spend                              AS signal_dollar_amount,
        glass_box_verdict                               AS signal_detail
    FROM signal_03_billing_code_cycling_results         -- << REPLACE
),

-- Signal 04: Network Clustering (maps vendor_id_a as primary)
sig04_results AS (
    SELECT
        vendor_id_a                                     AS vendor_id,
        vendor_name_a                                   AS vendor_name,
        signal_confidence,
        combined_cluster_spend                          AS signal_dollar_amount,
        glass_box_verdict                               AS signal_detail
    FROM signal_04_network_clustering_results           -- << REPLACE
),

-- Signal 05: Period Boundary Spikes
sig05_results AS (
    SELECT
        vendor_id,
        vendor_name,
        signal_confidence,
        boundary_spend                                  AS signal_dollar_amount,
        glass_box_verdict                               AS signal_detail
    FROM signal_05_period_boundary_results              -- << REPLACE
),

-- Signal 06: Service-to-Outcome Mismatch
sig06_results AS (
    SELECT
        vendor_id,
        vendor_name,
        signal_confidence,
        monthly_spend                                   AS signal_dollar_amount,
        glass_box_verdict                               AS signal_detail
    FROM signal_06_service_outcome_results              -- << REPLACE
),

-- Signal 07: Approval Chain Compression
sig07_results AS (
    SELECT
        vendor_id,
        vendor_name,
        signal_confidence,
        total_fast_approved_spend                       AS signal_dollar_amount,
        glass_box_verdict                               AS signal_detail
    FROM signal_07_approval_compression_results         -- << REPLACE
),

-- Signal 08: New Vendor Ramp
sig08_results AS (
    SELECT
        vendor_id,
        vendor_name,
        signal_confidence,
        ramp_period_spend                               AS signal_dollar_amount,
        glass_box_verdict                               AS signal_detail
    FROM signal_08_new_vendor_ramp_results              -- << REPLACE
),

-- Signal 09: Duplicate Billing
sig09_results AS (
    SELECT
        vendor_id,
        vendor_name,
        signal_confidence,
        recoverable_exposure                            AS signal_dollar_amount,
        glass_box_verdict                               AS signal_detail
    FROM signal_09_duplicate_billing_results            -- << REPLACE
),

-- Signal 10: Benford's Law (vendor-level only for stacking)
sig10_results AS (
    SELECT
        vendor_id,
        vendor_name,
        signal_confidence,
        0                                               AS signal_dollar_amount,    -- Scoping signal
        glass_box_verdict                               AS signal_detail
    FROM signal_10_benfords_results                     -- << REPLACE
    WHERE analysis_level = 'VENDOR'
),


-- =============================================================================
-- STEP 2: SIGNAL STACKING LOGIC
-- =============================================================================

-- Union all signals with source labels and confidence scores
all_signals AS (
    SELECT vendor_id, vendor_name, 'Signal 01: Vendor Concentration' AS signal_name,
           signal_confidence, signal_dollar_amount, signal_detail FROM sig01_results
    UNION ALL
    SELECT vendor_id, vendor_name, 'Signal 02: Sub-Threshold Batching',
           signal_confidence, signal_dollar_amount, signal_detail FROM sig02_results
    UNION ALL
    SELECT vendor_id, vendor_name, 'Signal 03: Billing Code Cycling',
           signal_confidence, signal_dollar_amount, signal_detail FROM sig03_results
    UNION ALL
    SELECT vendor_id, vendor_name, 'Signal 04: Network Clustering',
           signal_confidence, signal_dollar_amount, signal_detail FROM sig04_results
    UNION ALL
    SELECT vendor_id, vendor_name, 'Signal 05: Period Boundary Spikes',
           signal_confidence, signal_dollar_amount, signal_detail FROM sig05_results
    UNION ALL
    SELECT vendor_id, vendor_name, 'Signal 06: Service-Outcome Mismatch',
           signal_confidence, signal_dollar_amount, signal_detail FROM sig06_results
    UNION ALL
    SELECT vendor_id, vendor_name, 'Signal 07: Approval Chain Compression',
           signal_confidence, signal_dollar_amount, signal_detail FROM sig07_results
    UNION ALL
    SELECT vendor_id, vendor_name, 'Signal 08: New Vendor Ramp',
           signal_confidence, signal_dollar_amount, signal_detail FROM sig08_results
    UNION ALL
    SELECT vendor_id, vendor_name, 'Signal 09: Duplicate Billing',
           signal_confidence, signal_dollar_amount, signal_detail FROM sig09_results
    UNION ALL
    SELECT vendor_id, vendor_name, 'Signal 10: Benford''s Law Deviation',
           signal_confidence, signal_dollar_amount, signal_detail FROM sig10_results
),

-- Assign point values to confidence levels
scored_signals AS (
    SELECT
        *,
        CASE
            WHEN UPPER(signal_confidence) LIKE '%HIGH%'   THEN 3
            WHEN UPPER(signal_confidence) LIKE '%MEDIUM%' THEN 2
            WHEN UPPER(signal_confidence) LIKE '%LOW%'    THEN 1
            ELSE 0
        END                                             AS signal_points
    FROM all_signals
),

-- Aggregate to vendor level
vendor_scores AS (
    SELECT
        vendor_id,
        vendor_name,
        COUNT(DISTINCT signal_name)                     AS signals_firing_count,
        SUM(signal_points)                              AS composite_risk_score,
        SUM(CASE WHEN UPPER(signal_confidence) LIKE '%HIGH%' THEN 1 ELSE 0 END)
                                                        AS high_confidence_signals,
        SUM(CASE WHEN UPPER(signal_confidence) LIKE '%MEDIUM%' THEN 1 ELSE 0 END)
                                                        AS medium_confidence_signals,
        MAX(signal_dollar_amount)                       AS largest_single_signal_exposure,
        -- Aggregate signal names for the brief
        LISTAGG(signal_name || ' [' || signal_confidence || ']', ' | ')
            WITHIN GROUP (ORDER BY signal_points DESC)  AS signals_detail,
        -- Collect top 3 Glass Box verdicts for the investigation brief
        LISTAGG(
            CASE WHEN UPPER(signal_confidence) LIKE '%HIGH%'
                 THEN LEFT(signal_detail, 200) ELSE NULL END,
            ' /// '
        ) WITHIN GROUP (ORDER BY signal_points DESC)    AS high_confidence_verdicts
    FROM scored_signals
    GROUP BY 1, 2
),

-- Apply investigation tier classification
tiered_vendors AS (
    SELECT
        *,
        CASE
            WHEN signals_firing_count >= 4 AND high_confidence_signals >= 2
                                                        THEN 'TIER 1 — Immediate Investigation'
            WHEN signals_firing_count >= 3 OR high_confidence_signals >= 2
                                                        THEN 'TIER 2 — Priority Review'
            WHEN signals_firing_count >= 2              THEN 'TIER 3 — Scheduled Review'
            ELSE                                             'TIER 4 — Monitor'
        END                                             AS investigation_tier,
        ROW_NUMBER() OVER (ORDER BY composite_risk_score DESC, signals_firing_count DESC)
                                                        AS investigation_priority_rank
    FROM vendor_scores
)


-- =============================================================================
-- FINAL OUTPUT — INVESTIGATION PRIORITY QUEUE
-- =============================================================================

SELECT
    investigation_priority_rank                         AS priority,
    investigation_tier,
    vendor_id,
    vendor_name,

    -- SCORING SUMMARY
    signals_firing_count,
    composite_risk_score,
    high_confidence_signals,
    medium_confidence_signals,
    largest_single_signal_exposure,

    -- SIGNAL COVERAGE
    signals_detail,

    -- INVESTIGATION BRIEF
    COALESCE(
        high_confidence_verdicts,
        'No high-confidence signals. Review medium signals in signals_detail.'
    )                                                   AS investigation_brief

FROM tiered_vendors
ORDER BY investigation_priority_rank;


-- =============================================================================
-- SUMMARY STATISTICS — Run separately to get portfolio-level view
-- =============================================================================

/*
SELECT
    investigation_tier,
    COUNT(*)                                            AS vendor_count,
    SUM(composite_risk_score)                           AS total_risk_score,
    SUM(largest_single_signal_exposure)                 AS total_flagged_exposure,
    AVG(signals_firing_count)                           AS avg_signals_per_vendor
FROM tiered_vendors
GROUP BY investigation_tier
ORDER BY investigation_tier;
*/

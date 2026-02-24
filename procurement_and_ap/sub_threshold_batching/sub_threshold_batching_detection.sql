-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: SUB-THRESHOLD BATCHING
-- =============================================================================
-- File:     sub_threshold_batching_detection.sql
-- Signal:   02 of 10 — Procurement & AP
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Multiple invoices submitted to the same vendor within a rolling time window,
-- each individually below a defined approval threshold, but collectively
-- exceeding it. This is the AP equivalent of financial structuring — invoices
-- are deliberately sized to avoid triggering elevated approval requirements.
--
-- BEHAVIORAL TELL:
-- Legitimate vendors do not calibrate their invoice amounts to your internal
-- approval limits. When you see invoice clusters of $9,800 / $9,750 / $9,900
-- from the same vendor in the same month, that precision is the signal.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, vendor_id, vendor_name, invoice_amount,
--           invoice_date, cost_center_id, approved_by
-- Optional: purchase_order_id (improves false positive filtering)
--
-- TUNING PARAMETERS (adjust in Step 1 below):
-- * approval_threshold      — your company's single-invoice approval limit
-- * rolling_window_days     — how many days define a "cluster" (default: 30)
-- * min_invoices_in_cluster — minimum invoices to constitute a pattern (default: 2)
-- * cluster_multiple        — how far above threshold the cluster must be (default: 1.5x)
--
-- GLASS BOX OUTPUT:
-- Every flagged row includes: vendor name, cluster date range, number of
-- invoices in cluster, individual invoice amounts, combined cluster total,
-- your approval threshold, and the dollar gap above threshold.
-- A reviewer can reconstruct the entire finding from the output alone.
--
-- TYPICAL EXPOSURE RANGE: $25,000 — $500,000 per flagged vendor cluster
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- Edit this section. Do not edit below the divider.
-- =============================================================================

WITH normalized_ledger AS (

    SELECT
        invoice_id              AS transaction_id,          -- expected: VARCHAR / STRING
        po_number               AS purchase_order_id,       -- expected: VARCHAR (NULL ok)
        invoice_number          AS invoice_number,          -- expected: VARCHAR / STRING
        vendor_id               AS vendor_id,               -- expected: VARCHAR / STRING
        vendor_name             AS vendor_name,             -- expected: VARCHAR / STRING
        invoice_amount          AS invoice_amount,          -- expected: FLOAT (positive values)
        invoice_date            AS invoice_date,            -- expected: DATE
        cost_center_id          AS cost_center_id,          -- expected: VARCHAR / STRING
        approved_by_user_id     AS approved_by              -- expected: VARCHAR / STRING

    FROM your_internal_table_name   -- << CHANGE THIS

    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')

),

-- THRESHOLD CONFIGURATION
-- Adjust these values to match your company's approval policy.
thresholds AS (
    SELECT
        10000.00    AS approval_threshold,          -- Single-invoice limit requiring elevated approval
        30          AS rolling_window_days,         -- Days defining a cluster window
        2           AS min_invoices_in_cluster,     -- Minimum invoices to flag as a pattern
        1.5         AS cluster_multiple             -- Cluster must be >= this multiple of threshold
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- Do not edit below this line.
-- =============================================================================

-- Identify invoices that are individually below the approval threshold
sub_threshold_invoices AS (
    SELECT
        l.transaction_id,
        l.invoice_number,
        l.vendor_id,
        l.vendor_name,
        l.invoice_amount,
        l.invoice_date,
        l.cost_center_id,
        l.approved_by,
        t.approval_threshold,
        t.rolling_window_days,
        t.min_invoices_in_cluster,
        t.cluster_multiple
    FROM normalized_ledger l
    CROSS JOIN thresholds t
    WHERE l.invoice_amount < t.approval_threshold
      AND l.invoice_amount > 0
),

-- Build rolling clusters: for each invoice, find all invoices from the same
-- vendor within the rolling window that are also sub-threshold
invoice_clusters AS (
    SELECT
        a.vendor_id,
        a.vendor_name,
        a.cost_center_id,
        a.approved_by,
        a.approval_threshold,
        a.rolling_window_days,
        a.min_invoices_in_cluster,
        a.cluster_multiple,
        a.invoice_date                                      AS anchor_date,
        b.transaction_id                                    AS clustered_transaction_id,
        b.invoice_number                                    AS clustered_invoice_number,
        b.invoice_amount                                    AS clustered_invoice_amount,
        b.invoice_date                                      AS clustered_invoice_date
    FROM sub_threshold_invoices a
    JOIN sub_threshold_invoices b
        ON  a.vendor_id     = b.vendor_id
        AND a.cost_center_id = b.cost_center_id
        AND b.invoice_date  BETWEEN a.invoice_date
                                AND DATEADD('day', a.rolling_window_days, a.invoice_date)
),

-- Aggregate clusters and compute summary statistics
cluster_summary AS (
    SELECT
        vendor_id,
        vendor_name,
        cost_center_id,
        approved_by,
        approval_threshold,
        rolling_window_days,
        min_invoices_in_cluster,
        cluster_multiple,
        anchor_date                                         AS cluster_start_date,
        DATEADD('day', rolling_window_days, anchor_date)   AS cluster_end_date,
        COUNT(DISTINCT clustered_transaction_id)           AS invoice_count_in_cluster,
        SUM(clustered_invoice_amount)                      AS cluster_total,
        MIN(clustered_invoice_amount)                      AS min_invoice_in_cluster,
        MAX(clustered_invoice_amount)                      AS max_invoice_in_cluster,
        ROUND(AVG(clustered_invoice_amount), 2)            AS avg_invoice_in_cluster,
        LISTAGG(
            clustered_invoice_amount::VARCHAR || ' (' || clustered_invoice_date::VARCHAR || ')',
            ' | '
        ) WITHIN GROUP (ORDER BY clustered_invoice_date)   AS invoice_detail_log
    FROM invoice_clusters
    GROUP BY
        vendor_id, vendor_name, cost_center_id, approved_by,
        approval_threshold, rolling_window_days, min_invoices_in_cluster,
        cluster_multiple, anchor_date
),

-- Apply signal filters: cluster must exceed threshold by the configured multiple
-- and must contain the minimum number of invoices
flagged_clusters AS (
    SELECT
        vendor_id,
        vendor_name,
        cost_center_id,
        approved_by,
        cluster_start_date,
        cluster_end_date,
        invoice_count_in_cluster,
        cluster_total,
        approval_threshold,
        ROUND(cluster_total - approval_threshold, 2)           AS dollar_gap_above_threshold,
        ROUND(cluster_total / NULLIF(approval_threshold, 0), 2) AS threshold_multiple_exceeded,
        min_invoice_in_cluster,
        max_invoice_in_cluster,
        avg_invoice_in_cluster,
        invoice_detail_log,
        -- Confidence scoring: more invoices + higher multiple = higher confidence
        CASE
            WHEN invoice_count_in_cluster >= 5
             AND cluster_total >= cluster_multiple * 2 * approval_threshold THEN 'HIGH'
            WHEN invoice_count_in_cluster >= 3
             AND cluster_total >= cluster_multiple * approval_threshold      THEN 'MEDIUM'
            ELSE 'LOW'
        END AS signal_confidence
    FROM cluster_summary
    WHERE invoice_count_in_cluster >= min_invoices_in_cluster
      AND cluster_total             >= cluster_multiple * approval_threshold
),

-- Deduplicate: a vendor-window combination may appear as multiple anchor dates
-- Keep only the highest-value cluster per vendor per calendar month
deduped_clusters AS (
    SELECT *,
        ROW_NUMBER() OVER (
            PARTITION BY vendor_id, cost_center_id, DATE_TRUNC('month', cluster_start_date)
            ORDER BY cluster_total DESC
        ) AS row_rank
    FROM flagged_clusters
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    -- IDENTIFICATION
    vendor_id,
    vendor_name,
    cost_center_id,
    approved_by                                             AS approver_on_record,

    -- CLUSTER WINDOW
    cluster_start_date,
    cluster_end_date,
    rolling_window_days                                     AS window_days_used,

    -- SIGNAL METRICS
    invoice_count_in_cluster                                AS invoice_count,
    cluster_total                                           AS combined_cluster_total,
    approval_threshold                                      AS single_invoice_limit,
    dollar_gap_above_threshold                              AS excess_above_threshold,
    threshold_multiple_exceeded                             AS times_threshold_exceeded,

    -- INVOICE BREAKDOWN
    min_invoice_in_cluster                                  AS smallest_invoice,
    max_invoice_in_cluster                                  AS largest_invoice,
    avg_invoice_in_cluster                                  AS average_invoice,
    invoice_detail_log                                      AS all_invoices_in_cluster,

    -- VERDICT
    signal_confidence,
    'Sub-Threshold Batching'                                AS signal_name,
    'Vendor submitted ' || invoice_count_in_cluster::VARCHAR
        || ' invoices totaling $' || cluster_total::VARCHAR
        || ' within a ' || rolling_window_days::VARCHAR
        || '-day window. Each invoice individually below the $'
        || approval_threshold::VARCHAR
        || ' approval threshold. Combined total exceeds threshold by $'
        || dollar_gap_above_threshold::VARCHAR || '.'        AS glass_box_verdict

FROM deduped_clusters
WHERE row_rank = 1

ORDER BY
    signal_confidence DESC,
    cluster_total DESC;


-- =============================================================================
-- INVESTIGATIVE NEXT STEPS (for flagged vendors)
-- =============================================================================
-- 1. Pull all invoices from flagged vendor in the cluster window for manual review
-- 2. Verify PO numbers match approved purchase orders for each invoice
-- 3. Check whether the same approver processed all invoices in the cluster
-- 4. Cross-reference vendor against Signal 04 (Network Clustering) for shell
--    company indicators
-- 5. Request proof of delivery or service completion documentation
-- 6. Dollar exposure = cluster_total for each confirmed fraudulent cluster
-- =============================================================================

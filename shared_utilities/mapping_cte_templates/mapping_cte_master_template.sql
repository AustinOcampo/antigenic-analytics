-- =============================================================================
-- ANTIGENIC ANALYTICS — UNIVERSAL MAPPING CTE TEMPLATE
-- =============================================================================
-- File:    mapping_cte_master_template.sql
-- Version: 1.0.0
-- License: Apache 2.0
--
-- PURPOSE:
-- This is the master schema mapping template for all Antigenic Analytics
-- procurement and AP fraud signals. Copy this block to the top of any
-- signal query and complete Step 1 before running detection logic.
--
-- INSTRUCTIONS:
--   Step 1: Edit the Mapping CTE below. Change table names and column aliases
--           to match your internal schema. Do not rename the AS aliases.
--   Step 2: Run the validation query at the bottom to confirm your mapping.
--   Step 3: Paste your completed mapping CTE into any signal query file.
--           The detection logic references only the normalized column names.
--
-- SUPPORT:
--   Column type expectations are noted inline as comments.
--   If a column does not exist in your schema, see the NULL substitution
--   guidance at the bottom of this file.
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- This is the only section you edit.
-- =============================================================================

WITH normalized_ledger AS (

    SELECT

        -- TRANSACTION IDENTIFIERS
        invoice_id              AS transaction_id,          -- expected: VARCHAR / STRING
        po_number               AS purchase_order_id,       -- expected: VARCHAR / STRING (NULL if not applicable)
        invoice_number          AS invoice_number,          -- expected: VARCHAR / STRING

        -- VENDOR IDENTIFIERS
        vendor_id               AS vendor_id,               -- expected: VARCHAR / STRING
        vendor_name             AS vendor_name,             -- expected: VARCHAR / STRING
        vendor_tax_id           AS vendor_tax_id,           -- expected: VARCHAR / STRING (EIN / TIN)
        vendor_address          AS vendor_address,          -- expected: VARCHAR / STRING
        vendor_bank_routing     AS vendor_bank_routing,     -- expected: VARCHAR / STRING (NULL if not stored)

        -- FINANCIAL FIELDS
        invoice_amount          AS invoice_amount,          -- expected: FLOAT / NUMBER (positive values)
        invoice_currency        AS currency_code,           -- expected: VARCHAR (e.g., 'USD')
        payment_amount          AS payment_amount,          -- expected: FLOAT / NUMBER
        payment_status          AS payment_status,          -- expected: VARCHAR (e.g., 'PAID', 'PENDING', 'VOIDED')

        -- BILLING CLASSIFICATION
        cost_center_id          AS cost_center_id,          -- expected: VARCHAR / STRING
        department_name         AS department_name,         -- expected: VARCHAR / STRING
        gl_account_code         AS gl_account_code,         -- expected: VARCHAR (general ledger code)
        billing_code            AS billing_code,            -- expected: VARCHAR (service / product code)
        category_description    AS category_description,    -- expected: VARCHAR / STRING

        -- DATES AND TIMESTAMPS
        invoice_date            AS invoice_date,            -- expected: DATE
        invoice_received_date   AS received_date,           -- expected: DATE
        payment_date            AS payment_date,            -- expected: DATE
        created_at              AS submitted_timestamp,     -- expected: TIMESTAMP_NTZ

        -- APPROVAL CHAIN
        submitted_by_user_id    AS submitted_by,            -- expected: VARCHAR / STRING (employee ID)
        approved_by_user_id     AS approved_by,             -- expected: VARCHAR / STRING (approver employee ID)
        approved_at             AS approval_timestamp,      -- expected: TIMESTAMP_NTZ
        approval_level          AS approval_level,          -- expected: INTEGER or VARCHAR (e.g., 1, 2, 'MANAGER')

        -- VENDOR ONBOARDING (for new vendor ramp signal)
        vendor_created_date     AS vendor_onboard_date      -- expected: DATE (date vendor was added to master)

    FROM your_internal_table_name   -- << CHANGE THIS to your AP / invoice table

    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)   -- 2-year lookback (adjust if needed)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')   -- exclude reversed transactions

),


-- =============================================================================
-- STEP 2: DO NOT EDIT BELOW THIS LINE
-- Antigenic Analytics detection logic begins here.
-- All logic references normalized_ledger columns only.
-- =============================================================================

-- [ PASTE SIGNAL DETECTION CTE BLOCK HERE ]
-- Each signal file contains a self-contained detection block that
-- slots directly below this comment and above the final SELECT.


-- =============================================================================
-- VALIDATION QUERY — Run this first to confirm your mapping is working
-- =============================================================================
-- Uncomment and run this block independently before running any signal query.
-- It should return one row per column showing non-null counts and data types.
-- If a column returns 0 non-null rows, check your source table and column name.

/*
SELECT
    COUNT(*)                                    AS total_rows,
    COUNT(transaction_id)                       AS transaction_id_populated,
    COUNT(vendor_id)                            AS vendor_id_populated,
    COUNT(invoice_amount)                       AS invoice_amount_populated,
    COUNT(invoice_date)                         AS invoice_date_populated,
    COUNT(approved_by)                          AS approved_by_populated,
    COUNT(approval_timestamp)                   AS approval_timestamp_populated,
    COUNT(vendor_onboard_date)                  AS vendor_onboard_date_populated,
    MIN(invoice_date)                           AS earliest_invoice,
    MAX(invoice_date)                           AS latest_invoice,
    COUNT(DISTINCT vendor_id)                   AS distinct_vendors,
    COUNT(DISTINCT cost_center_id)              AS distinct_cost_centers,
    SUM(invoice_amount)                         AS total_invoice_volume
FROM normalized_ledger;
*/


-- =============================================================================
-- NULL SUBSTITUTION GUIDE
-- If a column doesn't exist in your schema, use these substitutions.
-- =============================================================================

-- Missing purchase_order_id:      NULL AS purchase_order_id
-- Missing vendor_tax_id:          NULL AS vendor_tax_id
-- Missing vendor_bank_routing:    NULL AS vendor_bank_routing
-- Missing approval_timestamp:     submitted_timestamp AS approval_timestamp
--                                 (signals requiring approval time will be degraded)
-- Missing vendor_onboard_date:    MIN(invoice_date) OVER (PARTITION BY vendor_id)
--                                 AS vendor_onboard_date
--                                 (approximated from first invoice seen)
-- Missing billing_code:           gl_account_code AS billing_code
--                                 (use GL code as proxy)

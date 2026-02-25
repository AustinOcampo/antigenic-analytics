-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: MULE ACCOUNT DETECTION
-- =============================================================================
-- File:     mule_account_detection.sql
-- Signal:   I04 of 05 — Identity & Origination
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Accounts used purely as pass-through vehicles for money movement rather
-- than for genuine banking activity. Mule accounts receive inbound transfers,
-- rapidly move the balance out via outbound transfers or cash withdrawals,
-- and show minimal retail transaction activity. They exist to launder
-- proceeds from fraud, scams, or theft — converting traceable electronic
-- funds into untraceable cash or crypto.
--
-- THE MULE PATTERN:
--   1. Account opens with small initial deposit or $0 (often deposit bonus)
--   2. Large inbound transfer arrives — often from a victim of a scam
--   3. Outbound transfer of 80-100% of balance within hours or days
--   4. Account goes quiet or repeats the cycle
--   5. No grocery stores, subscriptions, retail purchases — no real life
--
-- BEHAVIORAL TELL:
-- Real bank accounts have messy, human transaction patterns — coffee shops,
-- grocery stores, streaming subscriptions, irregular transfers. Mule accounts
-- are surgically clean: large in, large out, almost nothing else. The ratio
-- of transfer volume to retail transaction volume is the primary signal.
-- A legitimate account that moves $50K in transfers also has $3K in retail
-- spend. A mule account that moves $50K in transfers has $12 in retail spend.
--
-- DATA REQUIREMENTS:
-- Requires: account_id, transaction_id, transaction_amount, transaction_type,
--           transaction_timestamp, transaction_direction (debit/credit),
--           merchant_category_code (MCC) or transaction_category
-- Improves with: counterparty_account_id, transfer_method
--
-- TUNING PARAMETERS:
-- * min_transfer_volume      — minimum transfer activity to analyze (default: $5,000)
-- * max_retail_ratio         — retail spend / total inflow max for mule (default: 5%)
-- * rapid_outflow_hours      — hours after inflow within which outflow flags (default: 48)
-- * min_account_age_days     — minimum account age to analyze (default: 7)
--
-- TYPICAL EXPOSURE: $20,000 — $1,000,000 per mule network
-- =============================================================================

WITH normalized_transactions AS (

    SELECT
        account_id              AS account_id,              -- expected: VARCHAR
        transaction_id          AS transaction_id,          -- expected: VARCHAR
        transaction_amount      AS transaction_amount,      -- expected: FLOAT (positive)
        transaction_type        AS transaction_type,        -- expected: VARCHAR ('transfer','purchase','atm','deposit')
        transaction_direction   AS transaction_direction,   -- expected: VARCHAR ('credit','debit')
        transaction_timestamp   AS transaction_timestamp,   -- expected: TIMESTAMP_NTZ
        merchant_category       AS merchant_category,       -- expected: VARCHAR (NULL ok for transfers)
        counterparty_id         AS counterparty_id          -- expected: VARCHAR (NULL ok)

    FROM your_transactions_table    -- << CHANGE THIS

    WHERE transaction_timestamp >= DATEADD('day', -180, CURRENT_DATE)

),

normalized_accounts AS (

    SELECT
        account_id              AS account_id,
        opened_date             AS opened_date              -- expected: DATE

    FROM your_accounts_table        -- << CHANGE THIS

),

thresholds AS (
    SELECT
        5000    AS min_transfer_volume,
        5.0     AS max_retail_ratio_pct,
        48      AS rapid_outflow_hours,
        7       AS min_account_age_days
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Account-level transaction summary
account_summary AS (
    SELECT
        t.account_id,
        -- Inflows
        SUM(CASE WHEN t.transaction_direction = 'credit'
                  AND t.transaction_type IN ('transfer','ach','wire','deposit')
                 THEN t.transaction_amount ELSE 0 END)      AS transfer_inflow,
        -- Outflows
        SUM(CASE WHEN t.transaction_direction = 'debit'
                  AND t.transaction_type IN ('transfer','ach','wire','atm')
                 THEN t.transaction_amount ELSE 0 END)      AS transfer_outflow,
        -- Retail spend (the "real life" indicator)
        SUM(CASE WHEN t.transaction_type = 'purchase'
                 THEN t.transaction_amount ELSE 0 END)      AS retail_spend,
        -- Total activity
        SUM(t.transaction_amount)                           AS total_activity,
        COUNT(DISTINCT t.transaction_id)                    AS transaction_count,
        COUNT(DISTINCT t.counterparty_id)                   AS distinct_counterparties,
        COUNT(DISTINCT DATE_TRUNC('month', t.transaction_timestamp))
                                                            AS active_months,
        MIN(t.transaction_timestamp)                        AS first_transaction,
        MAX(t.transaction_timestamp)                        AS last_transaction
    FROM normalized_transactions t
    GROUP BY 1
),

-- Rapid outflow detection: large inflow followed by large outflow within 48 hours
rapid_outflow_events AS (
    SELECT
        a.account_id,
        COUNT(*)                                            AS rapid_cycle_count,
        SUM(a.transaction_amount)                           AS total_rapid_inflow
    FROM normalized_transactions a
    JOIN normalized_transactions b
        ON  a.account_id = b.account_id
        AND a.transaction_direction = 'credit'
        AND b.transaction_direction = 'debit'
        AND a.transaction_type IN ('transfer','ach','wire')
        AND b.transaction_type IN ('transfer','ach','wire','atm')
        AND b.transaction_timestamp BETWEEN a.transaction_timestamp
            AND DATEADD('hour', 48, a.transaction_timestamp)
        AND b.transaction_amount >= a.transaction_amount * 0.7  -- outflow >= 70% of inflow
    GROUP BY 1
),

-- Combine and score
account_scored AS (
    SELECT
        s.*,
        a.opened_date,
        DATEDIFF('day', a.opened_date, CURRENT_DATE)        AS account_age_days,
        COALESCE(r.rapid_cycle_count, 0)                    AS rapid_cycle_count,
        COALESCE(r.total_rapid_inflow, 0)                   AS total_rapid_inflow,
        ROUND(100.0 * s.retail_spend
            / NULLIF(s.transfer_inflow, 0), 2)              AS retail_to_inflow_ratio_pct,
        ROUND(s.transfer_outflow
            / NULLIF(s.transfer_inflow, 0), 4)              AS outflow_to_inflow_ratio,
        t.max_retail_ratio_pct,
        t.min_transfer_volume
    FROM account_summary s
    JOIN normalized_accounts a ON s.account_id = a.account_id
    LEFT JOIN rapid_outflow_events r ON s.account_id = r.account_id
    CROSS JOIN thresholds t
    WHERE
        s.transfer_inflow >= t.min_transfer_volume
        AND DATEDIFF('day', a.opened_date, CURRENT_DATE) >= t.min_account_age_days
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    account_id,
    opened_date,
    account_age_days,
    transfer_inflow,
    transfer_outflow,
    retail_spend,
    retail_to_inflow_ratio_pct,
    outflow_to_inflow_ratio,
    rapid_cycle_count,
    total_rapid_inflow,
    transaction_count,
    distinct_counterparties,
    active_months,

    CASE
        WHEN rapid_cycle_count >= 3
         AND retail_to_inflow_ratio_pct <= max_retail_ratio_pct
                                                            THEN 'HIGH — Active Mule'
        WHEN retail_to_inflow_ratio_pct <= max_retail_ratio_pct
         AND outflow_to_inflow_ratio >= 0.90               THEN 'HIGH — Pass-Through Pattern'
        WHEN rapid_cycle_count >= 1
         AND retail_to_inflow_ratio_pct <= max_retail_ratio_pct * 2
                                                            THEN 'MEDIUM — Mule Indicators'
        ELSE 'LOW'
    END                                                     AS signal_confidence,

    'Mule Account Detection'                                AS signal_name,
    'Account ' || account_id
        || ' received $' || ROUND(transfer_inflow, 0)::VARCHAR
        || ' in transfers and sent $' || ROUND(transfer_outflow, 0)::VARCHAR
        || ' out (' || ROUND(outflow_to_inflow_ratio * 100, 1)::VARCHAR
        || '% pass-through rate). Retail spend: $'
        || ROUND(retail_spend, 0)::VARCHAR
        || ' (' || retail_to_inflow_ratio_pct::VARCHAR
        || '% of inflows). Rapid in/out cycles: '
        || rapid_cycle_count::VARCHAR                       AS glass_box_verdict

FROM account_scored
WHERE
    retail_to_inflow_ratio_pct <= max_retail_ratio_pct * 2
    OR rapid_cycle_count >= 1

ORDER BY signal_confidence, transfer_inflow DESC;

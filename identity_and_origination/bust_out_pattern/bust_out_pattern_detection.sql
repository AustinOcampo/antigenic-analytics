-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: FIRST-PARTY FRAUD — BUST-OUT PATTERN
-- =============================================================================
-- File:     bust_out_pattern_detection.sql
-- Signal:   I05 of 05 — Identity & Origination
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Accounts that deliberately build a positive credit or repayment history
-- over a defined seasoning period, then systematically draw down to maximum
-- exposure — maxing credit lines, overdrafting accounts, taking maximum
-- cash advances — before going delinquent. This is first-party fraud:
-- the identity is real, the person is real, the intent to never repay
-- is the fraud.
--
-- THE BUST-OUT ARC:
--   Phase 1 — Seasoning (months 1-6+):
--     * Makes regular payments, often slightly above minimum
--     * Keeps utilization moderate to build trust
--     * May request and receive credit limit increases
--     * Behaves indistinguishably from a good customer
--
--   Phase 2 — Buildup (weeks before bust):
--     * Utilization starts climbing
--     * Transaction categories shift toward cash-equivalent purchases
--       (gift cards, money orders, crypto, wire-transferable goods)
--     * Payment amounts decrease or stop
--
--   Phase 3 — Extraction (the bust):
--     * Maximum cash advances taken
--     * Credit line maxed in compressed window
--     * Account goes delinquent immediately after
--
-- BEHAVIORAL TELL:
-- The utilization trajectory is the primary signal. Legitimate customers
-- who hit financial difficulty show gradual, irregular utilization increases
-- and reduced payments over many months. Bust-out fraudsters show a sharp,
-- deliberate utilization spike — often doubling utilization in 30-45 days —
-- concentrated in cash-equivalent categories, followed by immediate cessation
-- of payments.
--
-- DATA REQUIREMENTS:
-- Requires: account_id, statement_date, credit_limit, balance,
--           payment_amount, transaction_amount, transaction_category
-- Improves with: cash_advance_amount, credit_limit_increase_history
--
-- TUNING PARAMETERS:
-- * seasoning_months         — minimum months before bust detection (default: 3)
-- * utilization_spike_pct    — utilization increase that triggers flag (default: 40pp)
-- * cash_equiv_threshold     — % of spend in cash-equivalent categories (default: 40%)
-- * payment_drop_threshold   — payment reduction % before bust (default: 50%)
--
-- TYPICAL EXPOSURE: $10,000 — $200,000 per account
-- =============================================================================

WITH normalized_statements AS (

    SELECT
        account_id              AS account_id,              -- expected: VARCHAR
        statement_date          AS statement_date,          -- expected: DATE
        credit_limit            AS credit_limit,            -- expected: FLOAT
        balance                 AS balance,                 -- expected: FLOAT
        payment_amount          AS payment_amount,          -- expected: FLOAT (0 if no payment)
        minimum_payment_due     AS minimum_payment_due      -- expected: FLOAT

    FROM your_statements_table      -- << CHANGE THIS (monthly statement / balance table)

    WHERE statement_date >= DATEADD('month', -18, CURRENT_DATE)

),

normalized_transactions AS (

    SELECT
        account_id              AS account_id,
        transaction_amount      AS transaction_amount,
        transaction_timestamp   AS transaction_timestamp,
        -- Cash-equivalent categories: gift cards, money orders, crypto, wire transfers
        -- Map these to your MCC codes or category labels
        CASE WHEN transaction_category IN (
                'gift_card', 'money_order', 'crypto', 'wire_transfer',
                'cash_advance', 'money_service', 'gambling'
             )
             OR merchant_category_code IN ('6051','6211','7995','4829','6010','6011')
             THEN 1 ELSE 0 END AS is_cash_equivalent,
        transaction_category    AS transaction_category

    FROM your_transactions_table    -- << CHANGE THIS

    WHERE transaction_timestamp >= DATEADD('month', -18, CURRENT_DATE)

),

thresholds AS (
    SELECT
        3       AS seasoning_months,
        40.0    AS utilization_spike_pp,        -- Percentage point spike in utilization
        40.0    AS cash_equiv_threshold_pct,
        50.0    AS payment_drop_threshold_pct
),

-- Monthly utilization per account
monthly_utilization AS (
    SELECT
        account_id,
        statement_date,
        credit_limit,
        balance,
        payment_amount,
        minimum_payment_due,
        ROUND(100.0 * balance / NULLIF(credit_limit, 0), 1)
                                                        AS utilization_pct,
        -- Prior month utilization for trend
        LAG(ROUND(100.0 * balance / NULLIF(credit_limit, 0), 1))
            OVER (PARTITION BY account_id ORDER BY statement_date)
                                                        AS prior_month_utilization,
        -- 3-month average utilization (baseline)
        AVG(ROUND(100.0 * balance / NULLIF(credit_limit, 0), 1))
            OVER (PARTITION BY account_id
                  ORDER BY statement_date
                  ROWS BETWEEN 5 PRECEDING AND 2 PRECEDING)
                                                        AS avg_utilization_3_6mo_ago,
        ROW_NUMBER() OVER (PARTITION BY account_id ORDER BY statement_date)
                                                        AS month_number
    FROM normalized_statements
),

-- Cash-equivalent spend in recent months
recent_cash_equiv AS (
    SELECT
        account_id,
        SUM(transaction_amount)                         AS total_recent_spend,
        SUM(CASE WHEN is_cash_equivalent = 1
                 THEN transaction_amount ELSE 0 END)    AS cash_equiv_spend,
        ROUND(100.0 * SUM(CASE WHEN is_cash_equivalent = 1
                               THEN transaction_amount ELSE 0 END)
            / NULLIF(SUM(transaction_amount), 0), 1)   AS cash_equiv_pct
    FROM normalized_transactions
    WHERE transaction_timestamp >= DATEADD('month', -3, CURRENT_DATE)
    GROUP BY 1
),

-- Detect bust-out pattern: utilization spike + payment drop
bust_out_indicators AS (
    SELECT
        m.account_id,
        m.statement_date,
        m.credit_limit,
        m.balance,
        m.utilization_pct,
        m.avg_utilization_3_6mo_ago,
        m.payment_amount,
        m.prior_month_utilization,
        m.month_number,
        -- Utilization spike: current vs 3-6 month baseline
        ROUND(m.utilization_pct - COALESCE(m.avg_utilization_3_6mo_ago, 0), 1)
                                                        AS utilization_spike_pp,
        -- Payment drop: is the account paying less than before?
        LAG(m.payment_amount, 3) OVER (PARTITION BY m.account_id ORDER BY m.statement_date)
                                                        AS payment_3mo_ago,
        t.utilization_spike_pp                          AS spike_threshold,
        t.seasoning_months
    FROM monthly_utilization m
    CROSS JOIN thresholds t
    WHERE m.month_number >= t.seasoning_months
)

-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    b.account_id,
    b.statement_date,
    b.credit_limit,
    b.balance,
    b.utilization_pct                                   AS current_utilization_pct,
    b.avg_utilization_3_6mo_ago                         AS baseline_utilization_pct,
    b.utilization_spike_pp,
    b.payment_amount                                    AS last_payment_amount,
    b.payment_3mo_ago                                   AS payment_3mo_ago,
    ROUND(100.0 * (1 - b.payment_amount
        / NULLIF(b.payment_3mo_ago, 0)), 1)             AS payment_drop_pct,
    COALESCE(r.cash_equiv_pct, 0)                       AS cash_equiv_spend_pct,
    COALESCE(r.cash_equiv_spend, 0)                     AS cash_equiv_spend_amount,

    CASE
        WHEN b.utilization_spike_pp >= b.spike_threshold
         AND COALESCE(r.cash_equiv_pct, 0) >= 40
         AND b.payment_amount < b.payment_3mo_ago * 0.5  THEN 'HIGH — Bust-Out In Progress'
        WHEN b.utilization_spike_pp >= b.spike_threshold
         AND COALESCE(r.cash_equiv_pct, 0) >= 40         THEN 'HIGH — Spike + Cash Equiv'
        WHEN b.utilization_spike_pp >= b.spike_threshold  THEN 'MEDIUM — Utilization Spike'
        WHEN COALESCE(r.cash_equiv_pct, 0) >= 40
         AND b.utilization_pct >= 70                     THEN 'MEDIUM — High Util + Cash Equiv'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'First-Party Fraud — Bust-Out Pattern'              AS signal_name,
    'Account ' || b.account_id
        || ' utilization spiked ' || b.utilization_spike_pp::VARCHAR
        || ' percentage points (from '
        || ROUND(b.avg_utilization_3_6mo_ago, 0)::VARCHAR
        || '% to ' || b.utilization_pct::VARCHAR
        || '%). Cash-equivalent spend: '
        || COALESCE(r.cash_equiv_pct, 0)::VARCHAR
        || '% of recent transactions. Last payment: $'
        || ROUND(b.payment_amount, 0)::VARCHAR
        || ' vs $' || ROUND(b.payment_3mo_ago, 0)::VARCHAR || ' 3 months ago.'
                                                        AS glass_box_verdict

FROM bust_out_indicators b
LEFT JOIN recent_cash_equiv r ON b.account_id = r.account_id
CROSS JOIN thresholds t
WHERE
    b.utilization_spike_pp >= b.spike_threshold
    OR COALESCE(r.cash_equiv_pct, 0) >= t.cash_equiv_threshold_pct

ORDER BY signal_confidence, b.utilization_spike_pp DESC;

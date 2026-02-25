-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: POINTS LAUNDERING
-- =============================================================================
-- File:     points_laundering_detection.sql
-- Signal:   L06 of 10 — Loyalty & Rewards
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Points transferred between accounts in patterns that obscure their origin —
-- the loyalty equivalent of AP network clustering. Fraudsters who earn points
-- through illegitimate means (farming, compromised accounts, synthetic
-- transactions) need to move those points into a clean account before
-- redeeming. The transfer patterns reveal the laundering structure.
--
-- BEHAVIORAL TELL:
-- Legitimate point transfers are occasional and bilateral — a member
-- gifts points to a family member or pools with a partner. Laundering
-- transfers are unidirectional, concentrated, and often chain through
-- multiple accounts before reaching a redemption account. A member
-- who receives large point transfers from many different accounts
-- but has little organic accrual history is a redemption endpoint
-- in a laundering chain.
--
-- DATA REQUIREMENTS:
-- Requires: from_member_id, to_member_id, points_transferred,
--           transfer_timestamp, transfer_type
--
-- TUNING PARAMETERS:
-- * min_inbound_transfers    — inbound transfers before flagging (default: 3)
-- * min_points_received      — minimum transferred points (default: 10,000)
-- * transfer_to_earn_ratio   — received / organically earned ratio (default: 5x)
--
-- TYPICAL EXPOSURE: $50,000 — $500,000
-- =============================================================================

WITH normalized_transfers AS (
    SELECT
        from_member_id          AS from_member_id,          -- expected: VARCHAR
        to_member_id            AS to_member_id,            -- expected: VARCHAR
        points_transferred      AS points_transferred,      -- expected: FLOAT
        transfer_timestamp      AS transfer_timestamp,      -- expected: TIMESTAMP_NTZ
        transfer_type           AS transfer_type            -- expected: VARCHAR ('gift','pool','convert')
    FROM your_transfer_table        -- << CHANGE THIS
    WHERE transfer_timestamp >= DATEADD('year', -1, CURRENT_DATE)
),

normalized_accruals AS (
    SELECT
        member_id,
        SUM(points_earned)      AS organic_points_earned
    FROM your_accrual_ledger_table  -- << CHANGE THIS
    WHERE
        accrual_timestamp >= DATEADD('year', -1, CURRENT_DATE)
        AND accrual_reason = 'purchase'     -- organic only
    GROUP BY 1
),

thresholds AS (
    SELECT
        3       AS min_inbound_transfers,
        10000   AS min_points_received,
        5.0     AS transfer_to_earn_ratio
),

-- Inbound transfer summary per receiving member
inbound_summary AS (
    SELECT
        to_member_id                                    AS member_id,
        COUNT(DISTINCT from_member_id)                  AS distinct_senders,
        COUNT(*)                                        AS inbound_transfer_count,
        SUM(points_transferred)                         AS total_points_received,
        MIN(transfer_timestamp)                         AS first_transfer,
        MAX(transfer_timestamp)                         AS last_transfer,
        LISTAGG(from_member_id, ', ')
            WITHIN GROUP (ORDER BY points_transferred DESC)
                                                        AS sending_members
    FROM normalized_transfers
    GROUP BY 1
),

-- Outbound: did this member immediately transfer points out? (chain indicator)
outbound_summary AS (
    SELECT
        from_member_id                                  AS member_id,
        SUM(points_transferred)                         AS total_points_sent
    FROM normalized_transfers
    GROUP BY 1
)

SELECT
    i.member_id,
    i.distinct_senders,
    i.inbound_transfer_count,
    i.total_points_received,
    COALESCE(a.organic_points_earned, 0)                AS organic_points_earned,
    COALESCE(o.total_points_sent, 0)                    AS points_subsequently_transferred_out,
    ROUND(i.total_points_received
        / NULLIF(COALESCE(a.organic_points_earned, 1), 0), 2)
                                                        AS transfer_to_earn_ratio,
    i.sending_members,
    i.first_transfer,
    i.last_transfer,

    CASE
        WHEN i.distinct_senders >= 5
         AND i.total_points_received
             / NULLIF(COALESCE(a.organic_points_earned, 1), 0) >= t.transfer_to_earn_ratio
                                                        THEN 'HIGH — Redemption Endpoint'
        WHEN COALESCE(o.total_points_sent, 0) >= i.total_points_received * 0.7
                                                        THEN 'HIGH — Transfer Chain Node'
        WHEN i.distinct_senders >= t.min_inbound_transfers THEN 'MEDIUM — Multiple Senders'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'Points Laundering'                                 AS signal_name,
    'Member ' || i.member_id
        || ' received ' || ROUND(i.total_points_received, 0)::VARCHAR
        || ' points from ' || i.distinct_senders::VARCHAR
        || ' distinct accounts vs only '
        || ROUND(COALESCE(a.organic_points_earned, 0), 0)::VARCHAR
        || ' organically earned ('
        || ROUND(i.total_points_received
             / NULLIF(COALESCE(a.organic_points_earned, 1), 0), 1)::VARCHAR
        || 'x transfer-to-earn ratio). Senders: ' || i.sending_members
                                                        AS glass_box_verdict

FROM inbound_summary i
LEFT JOIN normalized_accruals a ON i.member_id = a.member_id
LEFT JOIN outbound_summary o ON i.member_id = o.member_id
CROSS JOIN thresholds t
WHERE
    i.inbound_transfer_count >= t.min_inbound_transfers
    AND i.total_points_received >= t.min_points_received

ORDER BY signal_confidence, total_points_received DESC;

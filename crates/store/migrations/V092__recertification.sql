-- Reviewing access on a frozen picture of it: a campaign takes one
-- snapshot of the edges in its scope, reviewers decide each, and the close
-- pulls what nobody stood behind. Items and decisions never change once
-- written, which is what makes the closing report reproducible.
CREATE TABLE recert_campaigns
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    campaign_id     text        NOT NULL,
    name            text        NOT NULL,
    -- Who is in scope: the whole realm, the holders of one role, or the
    -- members of one group.
    scope_kind      text        NOT NULL,
    scope_ref       text,
    reviewer_id     text        NOT NULL,
    state           text        NOT NULL DEFAULT 'draft',
    snapshot_at     timestamptz,
    closed_at       timestamptz,
    -- Edges left out of the snapshot because they are the reviewer's own:
    -- counted rather than hidden, since nobody certifies their own access.
    excluded        integer     NOT NULL DEFAULT 0,
    report_digest   bytea,
    report_envelope text,
    report_seq      bigint,
    created_by      text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    version         integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, campaign_id),
    CONSTRAINT recert_campaigns_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

CREATE TABLE recert_items
(
    tenant        text        NOT NULL,
    realm_id      text        NOT NULL,
    item_id       text        NOT NULL,
    campaign_id   text        NOT NULL,
    subject_id    text        NOT NULL,
    -- The edge under review, which is the edge a revocation would pull:
    -- a direct role, a group membership, or a governed grant.
    edge_kind     text        NOT NULL,
    edge_ref      text        NOT NULL,
    frozen        jsonb       NOT NULL,
    snapshot_hash bytea       NOT NULL,
    state         text        NOT NULL DEFAULT 'pending',
    resolution    text,
    resolved_at   timestamptz,

    PRIMARY KEY (tenant, realm_id, item_id),
    CONSTRAINT recert_items_campaign FOREIGN KEY (tenant, realm_id, campaign_id)
        REFERENCES recert_campaigns (tenant, realm_id, campaign_id) ON DELETE CASCADE,
    CONSTRAINT recert_items_once UNIQUE (tenant, realm_id, campaign_id, subject_id,
                                         edge_kind, edge_ref)
);
CREATE INDEX recert_items_campaign_idx ON recert_items (tenant, realm_id, campaign_id, state);

CREATE TABLE recert_decisions
(
    -- The order decisions were written in, which is what "the latest one"
    -- means: a clock read on two nodes cannot answer that.
    seq           bigserial,
    tenant        text        NOT NULL,
    realm_id      text        NOT NULL,
    decision_id   text        NOT NULL,
    campaign_id   text        NOT NULL,
    item_id       text        NOT NULL,
    reviewer_id   text        NOT NULL,
    decision      text        NOT NULL,
    justification text,
    decided_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, decision_id),
    CONSTRAINT recert_decisions_item FOREIGN KEY (tenant, realm_id, item_id)
        REFERENCES recert_items (tenant, realm_id, item_id) ON DELETE CASCADE
);
CREATE INDEX recert_decisions_item_idx ON recert_decisions (tenant, realm_id, item_id, seq);

GRANT SELECT, INSERT, UPDATE, DELETE ON recert_campaigns TO saffui_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON recert_items TO saffui_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON recert_decisions TO saffui_app;
GRANT USAGE ON SEQUENCE recert_decisions_seq_seq TO saffui_app;

ALTER TABLE recert_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE recert_campaigns FORCE ROW LEVEL SECURITY;
CREATE POLICY recert_campaigns_by_realm ON recert_campaigns
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE recert_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE recert_items FORCE ROW LEVEL SECURITY;
CREATE POLICY recert_items_by_realm ON recert_items
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE recert_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE recert_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY recert_decisions_by_realm ON recert_decisions
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

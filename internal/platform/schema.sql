-- Version 1. All instants use timestamptz; clients display in their own timezone.
CREATE TABLE IF NOT EXISTS schema_versions(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS users (
 id text PRIMARY KEY, email text UNIQUE NOT NULL, password bytea NOT NULL,
 role text NOT NULL CHECK(role IN ('super','operator','user')), disabled boolean NOT NULL DEFAULT false,
 totp text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions(hash text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS nodes (
 id text PRIMARY KEY, name text NOT NULL, host text NOT NULL, token_hash text NOT NULL,
 control_start int NOT NULL CHECK(control_start BETWEEN 1024 AND 65535), control_end int NOT NULL CHECK(control_end BETWEEN control_start AND 65535),
 port_start int NOT NULL CHECK(port_start BETWEEN 1024 AND 65535), port_end int NOT NULL CHECK(port_end BETWEEN port_start AND 65535),
 enabled boolean NOT NULL DEFAULT true, last_seen timestamptz,
 CHECK(control_end < port_start OR port_end < control_start)
);
CREATE TABLE IF NOT EXISTS plans (
 id text PRIMARY KEY, name text NOT NULL, node_id text NOT NULL REFERENCES nodes(id),
 max_devices int NOT NULL CHECK(max_devices BETWEEN 1 AND 16), max_tunnels int NOT NULL CHECK(max_tunnels BETWEEN 1 AND 128),
 tunnel_kibps int NOT NULL CHECK(tunnel_kibps BETWEEN 1 AND 1048576), price_cents bigint NOT NULL DEFAULT 0 CHECK(price_cents>=0),
 active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now()
);
-- Plans are immutable snapshots. New rules get a new ID; disabling sales does not revoke purchased rights.
CREATE TABLE IF NOT EXISTS entitlements(user_id text PRIMARY KEY REFERENCES users(id), plan_id text NOT NULL REFERENCES plans(id), expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS batches (
 id text PRIMARY KEY, name text NOT NULL, note text NOT NULL, plan_id text NOT NULL REFERENCES plans(id),
 seconds bigint NOT NULL CHECK(seconds BETWEEN 1 AND 315360000), deadline timestamptz NOT NULL, created_by text NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cards(hash text PRIMARY KEY, batch_id text NOT NULL REFERENCES batches(id), disabled boolean NOT NULL DEFAULT false);
CREATE TABLE IF NOT EXISTS redemptions (
 id text PRIMARY KEY, card_hash text UNIQUE NOT NULL REFERENCES cards(hash), user_id text NOT NULL REFERENCES users(id),
 batch_id text NOT NULL REFERENCES batches(id), request_id text NOT NULL, before_at timestamptz, after_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(user_id, request_id)
);
CREATE TABLE IF NOT EXISTS adjustments (
 id text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), actor text NOT NULL REFERENCES users(id),
 seconds bigint NOT NULL, reason text NOT NULL, before_at timestamptz NOT NULL, after_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bind_codes(hash text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), name text NOT NULL, expires_at timestamptz NOT NULL, used boolean NOT NULL DEFAULT false);
CREATE TABLE IF NOT EXISTS devices (
 id text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), node_id text NOT NULL REFERENCES nodes(id),
 name text NOT NULL, token_hash text NOT NULL, generation int NOT NULL DEFAULT 1,
 control_port int NOT NULL, revoked boolean NOT NULL DEFAULT false, UNIQUE(node_id, control_port), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tunnels (
 id text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), device_id text NOT NULL REFERENCES devices(id), node_id text NOT NULL REFERENCES nodes(id),
 name text NOT NULL, protocol text NOT NULL CHECK(protocol IN ('tcp','udp')), local_host text NOT NULL, local_port int NOT NULL CHECK(local_port BETWEEN 1 AND 65535),
 remote_port int NOT NULL CHECK(remote_port BETWEEN 1024 AND 65535), paused boolean NOT NULL DEFAULT false, UNIQUE(node_id,remote_port)
);
CREATE TABLE IF NOT EXISTS audit (
 id bigserial PRIMARY KEY, actor text NOT NULL, action text NOT NULL, target text NOT NULL, detail jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tunnel_user ON tunnels(user_id);
CREATE INDEX IF NOT EXISTS device_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS redemption_user ON redemptions(user_id,created_at DESC);
INSERT INTO schema_versions(version) VALUES(1) ON CONFLICT DO NOTHING;

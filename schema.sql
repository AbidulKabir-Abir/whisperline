-- WhisperLine Database Schema
-- IMPORTANT: This schema stores ONLY encrypted ciphertexts.
-- The server never has access to plaintext message content.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Users ──────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_tag      CHAR(9) UNIQUE NOT NULL,     -- @A7K2M9X4 format
    display_name  VARCHAR(64),
    -- Identity key bundle (public keys only — never private)
    ik_pub        BYTEA NOT NULL,              -- Ed25519 identity key (public)
    spk_pub       BYTEA NOT NULL,              -- Signed prekey (public)
    spk_sig       BYTEA NOT NULL,              -- Signature of spk_pub with ik_pub
    spk_id        INTEGER NOT NULL DEFAULT 1,
    -- One-time prekeys pool (public only)
    otpk_count    INTEGER NOT NULL DEFAULT 0,
    -- WebAuthn
    webauthn_id   BYTEA,
    webauthn_cred JSONB,
    -- Metadata
    last_seen     TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── One-Time Prekeys Pool ──────────────────────────────────────────────────
CREATE TABLE one_time_prekeys (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id     INTEGER NOT NULL,
    pub_key    BYTEA NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, key_id)
);

-- ── Conversations ─────────────────────────────────────────────────────────
CREATE TABLE conversations (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE conversation_members (
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (conversation_id, user_id)
);

-- ── Messages ──────────────────────────────────────────────────────────────
-- CRITICAL: ciphertext column contains ONLY client-encrypted AES-GCM blobs.
-- Neither the server nor the DBA can decrypt these without the recipient's private key.
CREATE TABLE messages (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id       UUID NOT NULL REFERENCES users(id),
    -- Encrypted payload per recipient (map of user_id → encrypted_blob)
    -- Each value is: nonce(12B) || ciphertext encrypted with session key
    encrypted_for   JSONB NOT NULL,            -- { "<recipient_user_id>": "<base64_ciphertext>" }
    -- Ratchet state (opaque to server)
    dh_pub          BYTEA,                     -- Sender's current ratchet public key
    prev_chain_len  INTEGER,
    msg_index       INTEGER,
    -- Delivery
    delivered_at    TIMESTAMPTZ,
    read_at         TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Encrypted File References ─────────────────────────────────────────────
-- File content lives in MinIO as encrypted blobs; this table only stores refs
CREATE TABLE file_refs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id      UUID REFERENCES messages(id) ON DELETE CASCADE,
    uploader_id     UUID NOT NULL REFERENCES users(id),
    minio_key       TEXT NOT NULL,             -- path in MinIO (opaque)
    encrypted_meta  BYTEA NOT NULL,            -- {name,size,mime} encrypted client-side
    size_bytes      BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Sessions ──────────────────────────────────────────────────────────────
CREATE TABLE sessions (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,                 -- bcrypt(token)
    device_id  TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Indexes ───────────────────────────────────────────────────────────────
CREATE INDEX idx_messages_conv ON messages(conversation_id, created_at DESC);
CREATE INDEX idx_messages_sender ON messages(sender_id);
CREATE INDEX idx_otpk_user ON one_time_prekeys(user_id) WHERE used = false;
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_conv_members_user ON conversation_members(user_id);

-- ── Auto-update timestamp ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE shares (
    share_id BYTEA NOT NULL CHECK (LENGTH(share_id) = 32),
    share_name TEXT NOT NULL,
    server_name TEXT NOT NULL,
    api_password TEXT NOT NULL DEFAULT '',
    bucket TEXT NOT NULL DEFAULT '',
    remark TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT share_id_name UNIQUE (share_id, share_name)
);

CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,
    account_name TEXT NOT NULL,
    account_password TEXT NOT NULL,
    workgroup TEXT NOT NULL
);

CREATE TABLE policies (
    share_id BYTEA NOT NULL,
    share_name TEXT NOT NULL,
    account INT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    read_access BOOLEAN NOT NULL,
    write_access BOOLEAN NOT NULL,
    delete_access BOOLEAN NOT NULL,
    execute_access BOOLEAN NOT NULL,
    CONSTRAINT policies_share_fk FOREIGN KEY (share_id, share_name) REFERENCES shares(share_id, share_name) ON DELETE CASCADE,
    CONSTRAINT share_account UNIQUE (share_id, share_name, account)
);
CREATE INDEX idx_policies_account ON policies (account);

CREATE TABLE bans (
    host TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);
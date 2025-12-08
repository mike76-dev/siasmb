CREATE TABLE shares (
    share_id BYTEA UNIQUE NOT NULL CHECK (LENGTH(share_id) = 32),
    share_name TEXT NOT NULL,
    server_name TEXT NOT NULL,
    api_password TEXT NOT NULL,
    bucket TEXT NOT NULL DEFAULT '',
    remark TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,
    account_name TEXT NOT NULL,
    account_password TEXT NOT NULL,
    workgroup TEXT NOT NULL
);

CREATE TABLE policies (
    share_id BYTEA REFERENCES shares(share_id) ON DELETE CASCADE,
    account INT REFERENCES accounts(id) ON DELETE CASCADE,
    read_access BOOLEAN NOT NULL,
    write_access BOOLEAN NOT NULL,
    delete_access BOOLEAN NOT NULL,
    execute_access BOOLEAN NOT NULL
);

CREATE TABLE bans (
    host TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);
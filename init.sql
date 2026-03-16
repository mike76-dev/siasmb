CREATE TABLE shares (
    share_name TEXT NOT NULL UNIQUE,
    share_type TEXT NOT NULL,
    server_name TEXT NOT NULL,
    api_password TEXT NOT NULL DEFAULT '',
    bucket TEXT NOT NULL DEFAULT '',
    remark TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    app_key BYTEA
);

CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,
    account_name TEXT NOT NULL,
    account_password TEXT NOT NULL,
    workgroup TEXT NOT NULL
);

CREATE TABLE policies (
    share_name TEXT NOT NULL,
    account INT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    read_access BOOLEAN NOT NULL,
    write_access BOOLEAN NOT NULL,
    delete_access BOOLEAN NOT NULL,
    execute_access BOOLEAN NOT NULL,
    CONSTRAINT policies_share_fk FOREIGN KEY (share_name) REFERENCES shares(share_name) ON DELETE CASCADE,
    CONSTRAINT share_account UNIQUE (share_name, account)
);
CREATE INDEX idx_policies_account ON policies (account);

CREATE TABLE bans (
    host TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE directories (
    id BIGSERIAL,
    share_name TEXT NOT NULL,
    parent_id BIGINT,
    name TEXT NOT NULL,
    full_path TEXT NOT NULL,
    account INT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    private BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (share_name, id),
    CONSTRAINT directories_id_unique UNIQUE (id),
    CONSTRAINT directories_share_fk FOREIGN KEY (share_name) REFERENCES shares(share_name) ON DELETE CASCADE,
    CONSTRAINT directories_parent_fk FOREIGN KEY (share_name, parent_id) REFERENCES directories(share_name, id) ON DELETE CASCADE,
    CONSTRAINT directories_unique_path UNIQUE (share_name, full_path),
    CONSTRAINT directories_unique_entry UNIQUE (share_name, parent_id, name)
);

CREATE TABLE objects (
    id BIGSERIAL PRIMARY KEY,
    share_name TEXT NOT NULL,
    directory_id BIGINT,
    name TEXT NOT NULL,
    full_path TEXT NOT NULL,
    object_key BYTEA NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    account INT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    private BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT objects_share_fk FOREIGN KEY (share_name) REFERENCES shares(share_name) ON DELETE CASCADE,
    CONSTRAINT objects_directory_fk FOREIGN KEY (share_name, directory_id) REFERENCES directories(share_name, id) ON DELETE CASCADE,
    CONSTRAINT objects_key_length CHECK (octet_length(object_key) = 32),
    CONSTRAINT objects_unique_path UNIQUE (share_name, full_path),
    CONSTRAINT objects_unique_entry UNIQUE (share_name, directory_id, name)
);

CREATE INDEX idx_directories_lookup_path ON directories (share_name, full_path);
CREATE INDEX idx_directories_lookup_parent ON directories (parent_id);
CREATE INDEX idx_directories_list ON directories (share_name, parent_id, name);
CREATE INDEX idx_objects_lookup_path ON objects (share_name, full_path);
CREATE INDEX idx_objects_list ON objects (share_name, directory_id, name);
CREATE INDEX idx_objects_key ON objects (object_key);
CREATE INDEX idx_objects_lookup_directory ON objects (directory_id);

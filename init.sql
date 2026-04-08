CREATE TABLE shares (
    share_name TEXT NOT NULL UNIQUE,
    share_type TEXT NOT NULL,
    server_name TEXT NOT NULL,
    api_password TEXT NOT NULL DEFAULT '',
    bucket TEXT NOT NULL DEFAULT '',
    remark TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    data_shards INT NOT NULL DEFAULT 0,
    parity_shards INT NOT NULL DEFAULT 0,
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
    size BIGINT NOT NULL DEFAULT 0,
    account INT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    private BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT objects_share_fk FOREIGN KEY (share_name) REFERENCES shares(share_name) ON DELETE CASCADE,
    CONSTRAINT objects_directory_fk FOREIGN KEY (share_name, directory_id) REFERENCES directories(share_name, id) ON DELETE CASCADE,
    CONSTRAINT objects_unique_path UNIQUE (share_name, full_path),
    CONSTRAINT objects_unique_entry UNIQUE (share_name, directory_id, name)
);

CREATE INDEX idx_directories_lookup_path ON directories (share_name, full_path);
CREATE INDEX idx_directories_lookup_parent ON directories (parent_id);
CREATE INDEX idx_directories_list ON directories (share_name, parent_id, name);
CREATE INDEX idx_objects_lookup_path ON objects (share_name, full_path);
CREATE INDEX idx_objects_list ON objects (share_name, directory_id, name);
CREATE INDEX idx_objects_lookup_directory ON objects (directory_id);

CREATE TABLE buffers (
    id BIGSERIAL PRIMARY KEY,
    share_name TEXT NOT NULL,
    data BYTEA NOT NULL,
    CONSTRAINT buffers_share_fk FOREIGN KEY (share_name) REFERENCES shares(share_name) ON DELETE CASCADE
);

CREATE TABLE metadata (
    id BIGSERIAL PRIMARY KEY,
    object_id BIGINT NOT NULL,
    obj_offset BIGINT NOT NULL,
    slab_key BYTEA,
    buffer_id BIGINT,
    data_offset BIGINT NOT NULL,
    data_length BIGINT NOT NULL,
    CONSTRAINT metadata_object_fk FOREIGN KEY (object_id) REFERENCES objects(id) ON DELETE CASCADE,
    CONSTRAINT metadata_slab_key_length CHECK (slab_key IS NULL OR octet_length(slab_key) = 32),
    CONSTRAINT metadata_buffer_fk FOREIGN KEY (buffer_id) REFERENCES buffers(id),
    CONSTRAINT metadata_storage_check CHECK (
        (slab_key IS NOT NULL AND buffer_id IS NULL) OR
        (slab_key IS NULL AND buffer_id IS NOT NULL)
    )
);

CREATE INDEX idx_metadata_object ON metadata (object_id);
CREATE INDEX idx_metadata_offset ON metadata (object_id, obj_offset);
CREATE INDEX idx_metadata_slab_key ON metadata (slab_key);
CREATE INDEX idx_metadata_slab_key_offset ON metadata (slab_key, data_offset);
CREATE UNIQUE INDEX idx_metadata_object_offset ON metadata (object_id, obj_offset);

CREATE TABLE uploads (
    id BIGSERIAL PRIMARY KEY,
    upload_id BYTEA NOT NULL UNIQUE,
    share_name TEXT NOT NULL,
    directory_id BIGINT,
    name TEXT NOT NULL,
    full_path TEXT NOT NULL,
    account INT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    private BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uploads_share_fk FOREIGN KEY (share_name) REFERENCES shares(share_name) ON DELETE CASCADE,
    CONSTRAINT uploads_directory_fk FOREIGN KEY (share_name, directory_id) REFERENCES directories(share_name, id) ON DELETE CASCADE,
    CONSTRAINT uploads_id_length CHECK (octet_length(upload_id) = 32),
    CONSTRAINT uploads_unique_path UNIQUE (share_name, full_path)
);

CREATE TABLE parts (
    id BIGSERIAL PRIMARY KEY,
    upload_id BIGINT NOT NULL,
    part_number INT NOT NULL,
    obj_offset BIGINT NOT NULL,
    slab_key BYTEA,
    buffer_id BIGINT,
    data_offset BIGINT NOT NULL,
    data_length BIGINT NOT NULL,
    CONSTRAINT parts_upload_fk FOREIGN KEY (upload_id) REFERENCES uploads(id) ON DELETE CASCADE,
    CONSTRAINT parts_key_length CHECK (slab_key IS NULL OR octet_length(slab_key) = 32),
    CONSTRAINT parts_unique_part UNIQUE (upload_id, obj_offset),
    CONSTRAINT parts_unique_part_number UNIQUE (upload_id, part_number),
    CONSTRAINT parts_buffer_fk FOREIGN KEY (buffer_id) REFERENCES buffers(id),
    CONSTRAINT parts_storage_check CHECK (
        (slab_key IS NOT NULL AND buffer_id IS NULL) OR
        (slab_key IS NULL AND buffer_id IS NOT NULL)
    )
);

CREATE INDEX idx_uploads_lookup_path ON uploads (share_name, full_path);
CREATE INDEX idx_uploads_lookup_directory ON uploads (directory_id);
CREATE INDEX idx_uploads_id ON uploads (upload_id);
CREATE INDEX idx_uploads_account ON uploads (account);
CREATE INDEX idx_parts_upload ON parts (upload_id);
CREATE INDEX idx_parts_number ON parts (upload_id, part_number);
CREATE UNIQUE INDEX idx_parts_upload_offset ON parts (upload_id, obj_offset);
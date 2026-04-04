package stores

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"go.sia.tech/core/types"
)

// SlabSlice represents a slice of data within an uploaded slab.
type SlabSlice struct {
	Key    types.Hash256
	Offset uint64
	Length uint64
	At     uint64
	Data   []byte
}

// CreateUpload creates a new upload entry in the database and returns the generated upload ID.
func (db *Database) CreateUpload(acc Account, share, path string, private bool) (uploadID string, err error) {
	path = normalizePath(path)
	dir, name := splitPath(path)
	if name == "" {
		return "", ErrNameInvalid
	}

	id := make([]byte, 32)
	rand.Read(id)
	uploadID = hex.EncodeToString(id)

	err = db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			WITH caller AS (
				SELECT id, workgroup
				FROM accounts
				WHERE id = $3
			),
			parent AS (
				SELECT d.id, d.full_path
				FROM directories d
				JOIN accounts owner ON owner.id = d.account
				CROSS JOIN caller c
				WHERE d.share_name = $1
					AND d.full_path = $2
					AND (
						d.account = c.id
						OR (d.private = FALSE AND owner.workgroup = c.workgroup)
					)

				UNION ALL

				SELECT NULL::bigint, '/'
				FROM caller
				WHERE $2 = '/'
			)
			INSERT INTO uploads (
				upload_id,
				share_name,
				directory_id,
				name,
				full_path,
				account,
				private
			)
			SELECT
				$4,
				$1,
				p.id,
				$5,
				$6,
				$3,
				$7
			FROM parent p
		`

		_, err = tx.Exec(ctx, query, share, dir, acc.ID, id, name, path, private)
		return err
	})

	if err != nil {
		return "", err
	}
	return
}

// RemoveUpload deletes an upload entry from the database and removes any associated
// buffers that are not referenced by other uploads or metadata entries.
func (db *Database) RemoveUpload(uploadID string) error {
	id, err := hex.DecodeString(uploadID)
	if err != nil {
		return err
	}

	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			WITH doomed_upload AS (
				SELECT id
				FROM uploads
				WHERE upload_id = $1
			),
			doomed_buffers AS (
				SELECT DISTINCT p.buffer_id
				FROM parts p
				JOIN doomed_upload u ON u.id = p.upload_id
				WHERE p.buffer_id IS NOT NULL
			),
			deleted_upload AS (
				DELETE FROM uploads u
				USING doomed_upload d
				WHERE u.id = d.id
				RETURNING u.id
			)
			DELETE FROM buffers b
			USING doomed_buffers db
			WHERE b.id = db.buffer_id
				AND NOT EXISTS (
					SELECT 1 FROM parts p WHERE p.buffer_id = b.id
				)
				AND NOT EXISTS (
					SELECT 1 FROM metadata m WHERE m.buffer_id = b.id
				)
		`

		_, err := tx.Exec(ctx, query, id)
		return err
	})
}

// AddPartialData adds a new buffer entry for the provided data and
// associates it with the given upload ID and part number.
func (db *Database) AddPartialData(uploadID string, partNumber int, offset uint64, data []byte) error {
	id, err := hex.DecodeString(uploadID)
	if err != nil {
		return err
	}

	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const bufQuery = `
			INSERT INTO buffers (data)
			VALUES ($1)
			RETURNING id
		`

		var bufferID uint64
		if err := tx.QueryRow(ctx, bufQuery, data).Scan(&bufferID); err != nil {
			return fmt.Errorf("couldn't parse buffer ID: %v", err)
		}

		const partQuery = `
			INSERT INTO parts (
				upload_id,
				part_number,
				obj_offset,
				buffer_id,
				data_offset,
				data_length
			)
			SELECT
				u.id,
				$2,
				$3,
				$4,
				0,
				$5
			FROM uploads u
			WHERE u.upload_id = $1
		`

		_, err := tx.Exec(ctx, partQuery, id, partNumber, offset, bufferID, len(data))
		if err != nil {
			return fmt.Errorf("couldn't insert incomplete part: %v", err)
		}
		return nil
	})
}

// AddPart adds a new part entry for the provided slab key and
// associates it with the given upload ID and part number.
func (db *Database) AddPart(uploadID string, partNumber int, offset, dataOffset, dataLength uint64, slabKey []byte) error {
	id, err := hex.DecodeString(uploadID)
	if err != nil {
		return err
	}

	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			INSERT INTO parts (
				upload_id,
				part_number,
				obj_offset,
				slab_key,
				data_offset,
				data_length
			)
			SELECT
				u.id,
				$2,
				$3,
				$4,
				$5,
				$6
			FROM uploads u
			WHERE u.upload_id = $1
		`

		_, err := tx.Exec(ctx, query, id, partNumber, offset, slabKey, dataOffset, dataLength)
		if err != nil {
			return fmt.Errorf("couldn't insert part: %v", err)
		}
		return nil
	})
}

// FinalizeUpload creates a new object entry for the completed upload, copies
// all associated parts as metadata entries, and deletes the upload entry.
func (db *Database) FinalizeUpload(uploadID string) error {
	id, err := hex.DecodeString(uploadID)
	if err != nil {
		return err
	}

	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			WITH target_upload AS (
				SELECT
					u.id,
					u.share_name,
					u.directory_id,
					u.name,
					u.full_path,
					u.account,
					u.private
				FROM uploads u
				WHERE u.upload_id = $1
			),
			new_object AS (
				INSERT INTO objects (
					share_name,
					directory_id,
					name,
					full_path,
					size,
					account,
					private
				)
				SELECT
					u.share_name,
					u.directory_id,
					u.name,
					u.full_path,
					COALESCE(SUM(p.data_length), 0),
					u.account,
					u.private
				FROM target_upload u
				LEFT JOIN parts p ON p.upload_id = u.id
				GROUP BY
					u.id,
					u.share_name,
					u.directory_id,
					u.name,
					u.full_path,
					u.account,
					u.private
				RETURNING id
			),
			copied_metadata AS (
				INSERT INTO metadata (
					object_id,
					obj_offset,
					slab_key,
					buffer_id,
					data_offset,
					data_length
				)
				SELECT
					o.id,
					p.obj_offset,
					p.slab_key,
					p.buffer_id,
					p.data_offset,
					p.data_length
				FROM parts p
				JOIN target_upload u ON u.id = p.upload_id
				CROSS JOIN new_object o
				ORDER BY p.obj_offset
				RETURNING id
			),
			deketed_upload AS (
				DELETE FROM uploads u
				USING target_upload t
				WHERE u.id = t.id
				RETURNING u.id
			)
			SELECT id
			FROM new_object

		`

		var objectID uint64
		err := tx.QueryRow(ctx, query, id).Scan(&objectID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}

			return fmt.Errorf("couldn't finalize upload: %v", err)
		}

		return nil
	})
}

// ListUploadParts retrieves the slab keys of all parts associated with the given upload ID.
func (db *Database) ListUploadParts(uploadID string) (parts []types.Hash256, err error) {
	id, err := hex.DecodeString(uploadID)
	if err != nil {
		return nil, err
	}

	err = db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			SELECT p.slab_key
			FROM parts p
			JOIN uploads u ON u.id = p.upload_id
			WHERE u.upload_id = $1 AND p.slab_key IS NOT NULL
			ORDER BY p.obj_offset
		`

		rows, err := tx.Query(ctx, query, id)
		if err != nil {
			return fmt.Errorf("couldn't list upload parts: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var slabKey []byte
			if err := rows.Scan(&slabKey); err != nil {
				return fmt.Errorf("couldn't parse slab key: %v", err)
			}
			var hash types.Hash256
			copy(hash[:], slabKey)
			parts = append(parts, hash)
		}
		return rows.Err()
	})

	return parts, err
}

// ListSlabs retrieves the slab keys of all files at or down the specified path.
func (db *Database) ListSlabs(acc Account, share, path string) (slabs []types.Hash256, err error) {
	path = normalizePath(path)

	err = db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			WITH caller AS (
				SELECT id, workgroup
				FROM accounts
				WHERE id = $3
			),
			target_file AS (
				SELECT o.id, o.full_path
				FROM objects o
				JOIN accounts owner ON owner.id = o.account
				CROSS JOIN caller c
				WHERE o.share_name = $1
					AND o.full_path = $2
					AND (
						o.account = c.id
						OR (o.private = FALSE AND owner.workgroup = c.workgroup)
					)
			),
			target_dir AS (
				SELECT d.id, d.full_path
				FROM directories d
				JOIN accounts owner ON owner.id = d.account
				CROSS JOIN caller c
				WHERE d.share_name = $1
					AND d.full_path = $2
					AND (
						d.account = c.id
						OR (d.private = FALSE AND owner.workgroup = c.workgroup)
					)
			),
			visible_objects AS (
				SELECT o.id
				FROM objects o
				JOIN target_file tf ON tf.id = o.id

				UNION

				SELECT o.id
				FROM objects o
				JOIN accounts owner ON owner.id = o.account
				JOIN target_dir td ON TRUE
				CROSS JOIN caller c
				WHERE o.share_name = $1
					AND o.full_path LIKE td.full_path || '/%%'
					AND (
						o.account = c.id
						OR (o.private = FALSE AND owner.workgroup = c.workgroup)
					)
			),
			target_exists AS (
				SELECT EXISTS (SELECT 1 FROM target_file)
					OR EXISTS (SELECT 1 FROM target_dir) AS found
			)
			SELECT
				te.found,
				(
					SELECT COALESCE(
						ARRAY_AGG(DISTINCT m.slab_key),
						'{}'::bytea[]
					)
					FROM visible_objects vo
					JOIN metadata m ON m.object_id = vo.id
					WHERE m.slab_key IS NOT NULL
				) AS slab_keys
			FROM target_exists te

		`

		var found bool
		var rawKeys [][]byte

		if err := tx.QueryRow(ctx, query, share, path, acc.ID).Scan(&found, &rawKeys); err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}

		slabs = make([]types.Hash256, 0, len(rawKeys))
		for _, b := range rawKeys {
			if len(b) != 32 {
				return fmt.Errorf("invalid slab key length: %d", len(b))
			}
			var h types.Hash256
			copy(h[:], b)
			slabs = append(slabs, h)
		}
		return nil
	})

	return
}

// GetMetadata retrieves the metadata of the file at the specified path.
func (db *Database) GetMetadata(acc Account, share, path string) (slabs []SlabSlice, partial SlabSlice, err error) {
	path = normalizePath(path)

	err = db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			WITH caller AS (
				SELECT id, workgroup
				FROM accounts
				WHERE id = $3
			),
			target AS (
				SELECT o.id
				FROM objects o
				JOIN accounts owner ON owner.id = o.account
				CROSS JOIN caller c
				WHERE o.share_name = $1
					AND o.full_path = $2
					AND (
						o.account = c.id
						OR (o.private = FALSE AND owner.workgroup = c.workgroup)
					)
			)
			SELECT
				m.obj_offset,
				m.slab_key,
				m.data_offset,
				m.data_length,
				b.data
			FROM metadata m
			JOIN target t ON t.id = m.object_id
			LEFT JOIN buffers b ON b.id = m.buffer_id
			ORDER BY m.obj_offset
		`

		rows, err := tx.Query(ctx, query, share, path, acc.ID)
		if err != nil {
			return fmt.Errorf("failed to query object metadata: %v", err)
		}
		defer rows.Close()

		var found bool
		for rows.Next() {
			found = true

			var (
				objOffset  uint64
				slabKey    []byte
				dataOffset uint64
				dataLength uint64
				chunk      []byte
			)

			if err := rows.Scan(&objOffset, &slabKey, &dataOffset, &dataLength, &chunk); err != nil {
				return fmt.Errorf("failed to scan object metadata: %v", err)
			}

			if slabKey == nil {
				partial = SlabSlice{
					Offset: dataOffset,
					Length: dataLength,
					At:     objOffset,
					Data:   chunk[dataOffset : dataOffset+dataLength],
				}
				continue
			}

			if len(slabKey) != 32 {
				return fmt.Errorf("invalid key length: %d", len(slabKey))
			}

			var key types.Hash256
			copy(key[:], slabKey)
			slabs = append(slabs, SlabSlice{
				Key:    key,
				Offset: dataOffset,
				Length: dataLength,
				At:     objOffset,
			})
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed while reading object metadata: %v", err)
		}

		if found {
			return nil
		}

		return ErrNotFound
	})

	return
}

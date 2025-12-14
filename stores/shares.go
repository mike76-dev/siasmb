package stores

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"go.sia.tech/core/types"
)

// Share represents a renterd bucket, which is mounted as a remote share.
type Share struct {
	ID         types.Hash256
	Name       string
	ServerName string
	Password   string
	Bucket     string
	Remark     string
	CreatedAt  time.Time
}

// RegisterShare registers a new share in the database.
func (db *Database) RegisterShare(s Share) error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			INSERT INTO shares (share_id, share_name, server_name, api_password, bucket, remark, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`
		_, err := tx.Exec(ctx, query, s.ID[:], s.Name, s.ServerName, s.Password, s.Bucket, s.Remark, time.Now())
		if err != nil {
			return fmt.Errorf("failed to register share: %w", err)
		} else {
			return nil
		}
	})
}

// UnregisterShare removes the share from the database.
func (db *Database) UnregisterShare(id types.Hash256) error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			DELETE FROM shares
			WHERE share_id = $1
		`
		_, err := tx.Exec(ctx, query, id[:])
		if err != nil {
			return fmt.Errorf("failed to remove share: %w", err)
		} else {
			return nil
		}
	})
}

// GetShare tries to retrieve the share information by its ID and/or name.
// `renterd` doesn't support share IDs. On the other hand, `indexd` will
// support multiple shares with the same name, so the ID will be the only way
// to distinguish between the shares.
func (db *Database) GetShare(id types.Hash256, name string) (s Share, err error) {
	err = db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			SELECT share_name, server_name, api_password, bucket, remark, created_at
			FROM shares
			WHERE (share_id = '\x0000000000000000000000000000000000000000000000000000000000000000'
			AND share_name = $1)
			OR share_id = $2
		`
		var name, server, password, bucket, remark string
		var created time.Time
		err = tx.QueryRow(ctx, query, name, id[:]).Scan(&name, &server, &password, &bucket, &remark, &created)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("share not found")
		} else if err != nil {
			return fmt.Errorf("failed to retrieve share: %w", err)
		}
		s = Share{
			ID:         id,
			Name:       name,
			ServerName: server,
			Password:   password,
			Bucket:     bucket,
			Remark:     remark,
			CreatedAt:  created,
		}
		return nil
	})
	return
}

// GetShares lists all shares the specified account has access to.
func (db *Database) GetShares(acc Account) (shares []Share, err error) {
	err = db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			SELECT DISTINCT s.share_id, s.share_name, s.server_name, s.api_password, s.bucket, s.remark, s.created_at
			FROM shares AS s
			JOIN policies AS p
			ON ((p.share_id <> '\x0000000000000000000000000000000000000000000000000000000000000000' AND p.share_id = s.share_id)
			OR (p.share_id = '\x0000000000000000000000000000000000000000000000000000000000000000' AND p.share_name = s.share_name))
			WHERE p.account = $1
			AND (p.read_access
			OR p.write_access
			OR p.delete_access
			OR p.execute_access)
		`
		rows, err := tx.Query(ctx, query, acc.ID)
		if err != nil {
			return fmt.Errorf("failed to retrieve share: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			id := make([]byte, 32)
			var name, server, password, bucket, remark string
			var created time.Time
			if err := rows.Scan(&id, &name, &server, &password, &bucket, &remark, &created); err != nil {
				return fmt.Errorf("failed to retrieve share: %w", err)
			}
			shares = append(shares, Share{
				ID:         types.Hash256(id),
				Name:       name,
				ServerName: server,
				Password:   password,
				Bucket:     bucket,
				Remark:     remark,
				CreatedAt:  created,
			})
		}
		return nil
	})
	return
}

// GetPolicies lists all the accounts that can connect to the specified share.
func (db *Database) GetAccounts(sh Share) (ars []AccessRights, err error) {
	err = db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			SELECT account, read_access, write_access, delete_access, execute_access
			FROM policies
			WHERE (share_id = '\x0000000000000000000000000000000000000000000000000000000000000000'
			AND share_name = $1)
			OR share_id = $2
		`
		rows, err := tx.Query(ctx, query, sh.Name, sh.ID[:])
		if err != nil {
			return fmt.Errorf("failed to retrieve policies: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var accountID int
			var read, write, delete, execute bool
			if err := rows.Scan(&accountID, &read, &write, &delete, &execute); err != nil {
				return fmt.Errorf("failed to retrieve policies: %w", err)
			}
			ars = append(ars, AccessRights{
				ShareID:       sh.ID,
				ShareName:     sh.Name,
				AccountID:     accountID,
				ReadAccess:    read,
				WriteAccess:   write,
				DeleteAccess:  delete,
				ExecuteAccess: execute,
			})
		}
		return nil
	})
	return
}

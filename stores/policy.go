package stores

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"go.sia.tech/core/types"
)

// AccessRights describes the access policies of a user account.
type AccessRights struct {
	ShareID       types.Hash256
	ShareName     string
	AccountID     int
	ReadAccess    bool
	WriteAccess   bool
	DeleteAccess  bool
	ExecuteAccess bool
}

// GetAccessRights retrieves the access policy for the given account.
func (db *Database) GetAccessRights(share Share, acc Account) (ar AccessRights, err error) {
	err = db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			SELECT read_access, write_access, delete_access, execute_access
			FROM policies
			WHERE ((share_id = '\x0000000000000000000000000000000000000000000000000000000000000000'
			AND share_name = $1)
			OR share_id = $2)
			AND account = $3
		`
		var ra, wa, da, ea bool
		err = tx.QueryRow(ctx, query, share.Name, share.ID[:], acc.ID).Scan(&ra, &wa, &da, &ea)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("policy not found")
		} else if err != nil {
			return fmt.Errorf("failed to retrieve policy: %w", err)
		}
		ar = AccessRights{
			ShareID:       share.ID,
			ShareName:     share.Name,
			AccountID:     acc.ID,
			ReadAccess:    ra,
			WriteAccess:   wa,
			DeleteAccess:  da,
			ExecuteAccess: ea,
		}
		return nil
	})
	return
}

// SetAccessRights stores the access policy in the database.
func (db *Database) SetAccessRights(ar AccessRights) error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			INSERT INTO policies (share_id, share_name, account, read_access, write_access, delete_access, execute_access)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (share_id, share_name, account) DO UPDATE
			SET read_access = EXCLUDED.read_access,
				write_access = EXCLUDED.write_access,
				delete_access = EXCLUDED.delete_access,
				execute_access = EXCLUDED.execute_access
		`
		_, err := tx.Exec(ctx, query, ar.ShareID[:], ar.ShareName, ar.AccountID, ar.ReadAccess, ar.WriteAccess, ar.DeleteAccess, ar.ExecuteAccess)
		if err != nil {
			return fmt.Errorf("failed to update policy: %w", err)
		} else {
			return nil
		}
	})
}

// RemoveAccessRights removes the access policy to the share for the given account.
func (db *Database) RemoveAccessRights(share Share, acc Account) error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			DELETE FROM policies
			WHERE ((share_id = '\x0000000000000000000000000000000000000000000000000000000000000000'
			AND share_name = $1)
			OR share_id = $2)
			AND account = $3
		`
		_, err := tx.Exec(ctx, query, share.Name, share.ID, acc.ID)
		if err != nil {
			return fmt.Errorf("failed to remove policy: %w", err)
		} else {
			return nil
		}
	})
}

// ClearAccessRights removes all access rights for the given account.
func (db *Database) ClearAccessRights(acc Account) error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			DELETE FROM policies
			WHERE account = $1
		`
		_, err := tx.Exec(ctx, query, acc.ID)
		if err != nil {
			return fmt.Errorf("failed to remove policies: %w", err)
		} else {
			return nil
		}
	})
}

// FlagsFromAccessRights converts an AccessRights structure into SMB2 flags.
func FlagsFromAccessRights(ar AccessRights) uint32 {
	var flags uint32
	if ar.ReadAccess {
		flags |= 0x00120089 // FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
	}

	if ar.WriteAccess {
		flags |= 0x000c0116 // FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER
	}

	if ar.DeleteAccess {
		flags |= 0x00010040 // FILE_DELETE_CHILD | DELETE
	}

	if ar.ExecuteAccess {
		flags |= 0x00000020 // FILE_EXECUTE
	}

	return flags
}

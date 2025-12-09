package stores

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// IsBanned returns true if the remote host is banned. The ban reason is also returned.
func (db *Database) IsBanned(host string) (bool, string, error) {
	var reason string
	err := db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			SELECT reason
			FROM bans
			WHERE host = $1
		`
		return tx.QueryRow(ctx, query, host).Scan(&reason)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	} else if err != nil {
		return false, "", fmt.Errorf("failed to retrieve ban reason: %w", err)
	}
	return true, reason, err
}

// BanHost puts the host on the ban list.
func (db *Database) BanHost(host, reason string) error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			INSERT INTO bans (host, reason)
			VALUES ($1, $2)
			ON CONFLICT (host) DO NOTHING
		`
		_, err := tx.Exec(ctx, query, host, reason)
		if err != nil {
			return fmt.Errorf("failed to ban host: %w", err)
		} else {
			return nil
		}
	})
}

// UnbanHost removes the host from the ban list.
func (db *Database) UnbanHost(host string) error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			DELETE FROM bans
			WHERE host = $1
		`
		_, err := tx.Exec(ctx, query, host)
		if err != nil {
			return fmt.Errorf("failed to unban host: %w", err)
		} else {
			return nil
		}
	})
}

// ClearBans clears the ban list.
func (db *Database) ClearBans() error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = "DELETE FROM bans"
		_, err := tx.Exec(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to clear ban list: %w", err)
		} else {
			return nil
		}
	})
}

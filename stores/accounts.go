package stores

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Account represents a user account that can connect to particular shares.
type Account struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Workgroup string `json:"workgroup"`
}

// GetAccountByID tries to retrieve the account by its ID.
func (db *Database) GetAccountByID(id int) (acc Account, err error) {
	err = db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			SELECT account_name, account_password, workgroup
			FROM accounts
			WHERE id = $1
		`
		var username, password, workgroup string
		err = tx.QueryRow(ctx, query, id).Scan(&username, &password, &workgroup)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("account not found")
		} else if err != nil {
			return fmt.Errorf("failed to retrieve account: %w", err)
		}
		acc = Account{id, username, password, workgroup}
		return nil
	})
	return
}

// FindAccount tries to retrieve the account by the username and the workgroup.
func (db *Database) FindAccount(username, workgroup string) (acc Account, err error) {
	err = db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			SELECT id, account_password
			FROM accounts
			WHERE account_name = $1
			AND workgroup = $2
		`
		var id int
		var password string
		err = tx.QueryRow(ctx, query, username, workgroup).Scan(&id, &password)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("account not found")
		} else if err != nil {
			return fmt.Errorf("failed to retrieve account: %w", err)
		}
		acc = Account{id, username, password, workgroup}
		return nil
	})
	return
}

// AddAccount adds a new account to the database.
func (db *Database) AddAccount(acc Account) error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			INSERT INTO accounts (account_name, account_password, workgroup)
			VALUES ($1, $2, $3)
		`
		_, err := tx.Exec(ctx, query, acc.Username, acc.Password, acc.Workgroup)
		if err != nil {
			return fmt.Errorf("failed to add account: %w", err)
		} else {
			return nil
		}
	})
}

// HasAccount returns true if there is such account in the database.
func (db *Database) HasAccount(username, workgroup string) (bool, error) {
	var count int
	err := db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			SELECT COUNT(*)
			FROM accounts
			WHERE account_name = $1
			AND workgroup = $2
		`
		return tx.QueryRow(ctx, query, username, workgroup).Scan(&count)
	})
	return count > 0, err
}

// RemoveAccount removes the specified account from the database.
func (db *Database) RemoveAccount(username, workgroup string) error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			DELETE FROM accounts
			WHERE account_name = $1
			AND workgroup = $2
		`
		_, err := tx.Exec(ctx, query, username, workgroup)
		if err != nil {
			return fmt.Errorf("failed to remove account: %w", err)
		} else {
			return nil
		}
	})
}

// RemoveAccounts removes all accounts of the specified workgroup.
func (db *Database) RemoveAccounts(workgroup string) error {
	return db.txn(func(ctx context.Context, tx pgx.Tx) error {
		const query = `
			DELETE FROM accounts
			WHERE workgroup = $1
		`
		_, err := tx.Exec(ctx, query, workgroup)
		if err != nil {
			return fmt.Errorf("failed to remove accounts: %w", err)
		} else {
			return nil
		}
	})
}

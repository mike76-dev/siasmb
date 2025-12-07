package stores

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Database represents a PostgreSQL-backed store.
type Database struct {
	pool *pgxpool.Pool
}

// Close closes the underlying database connection.
func (db *Database) Close() {
	db.pool.Close()
}

// NewStore returns an initialized Database instance.
func NewStore(ctx context.Context, dc DatabaseConfig) (*Database, error) {
	pool, err := pgxpool.New(ctx, dc.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %w", err)
	} else if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	log.Printf("Connected to SQL database %s, %s:%d\n", dc.Database, dc.Host, dc.Port)
	return &Database{pool}, nil
}

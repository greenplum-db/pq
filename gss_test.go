package pq

import (
	"database/sql"
	"os"
	"testing"
)

func maybeSkipGSSTests(t *testing.T) {
	if os.Getenv("KRB5_KTNAME") == "" {
		t.Skip("KRB5_KTNAME not set, skipping GSS tests")
	}
}

func openGSSConn(t *testing.T, conninfo string) (*sql.DB, error) {
	db, err := openTestConnConninfo(conninfo)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err == nil {
		return db, tx.Rollback()
	}
	_ = db.Close()
	return nil, err
}

func TestGSSConnection(t *testing.T) {
	maybeSkipGSSTests(t)
	// TODO configurable user
	db, err := openGSSConn(t, "krbsrvname=postgres user=cc_user/krbserver.gpcc")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query("SELECT 1")
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
}

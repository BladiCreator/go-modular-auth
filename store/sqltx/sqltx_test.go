package sqltx_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/BladiCreator/go-modular-auth/store/sqltx"
)

type mockDriver struct {
	mu        sync.Mutex
	begun     int
	committed int
	rolled    int
}

var (
	testDrv  = &mockDriver{}
	drvOnce  sync.Once
	mockName = "mock_sqltx"
)

func initDriver() {
	drvOnce.Do(func() {
		sql.Register(mockName, testDrv)
	})
}

func (d *mockDriver) Open(name string) (driver.Conn, error) {
	return &mockConn{d: d}, nil
}

type mockConn struct {
	d *mockDriver
}

func (c *mockConn) Prepare(query string) (driver.Stmt, error) {
	return &mockStmt{}, nil
}

func (c *mockConn) Close() error { return nil }

func (c *mockConn) Begin() (driver.Tx, error) {
	c.d.mu.Lock()
	c.d.begun++
	c.d.mu.Unlock()
	return &mockTx{d: c.d}, nil
}

type mockTx struct {
	d *mockDriver
}

func (m *mockTx) Commit() error {
	m.d.mu.Lock()
	m.d.committed++
	m.d.mu.Unlock()
	return nil
}

func (m *mockTx) Rollback() error {
	m.d.mu.Lock()
	m.d.rolled++
	m.d.mu.Unlock()
	return nil
}

type mockStmt struct{}

func (s *mockStmt) Close() error  { return nil }
func (s *mockStmt) NumInput() int { return -1 }
func (s *mockStmt) Exec(args []driver.Value) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}
func (s *mockStmt) Query(args []driver.Value) (driver.Rows, error) { return &mockRows{}, nil }

type mockRows struct{}

func (r *mockRows) Columns() []string              { return []string{"col"} }
func (r *mockRows) Close() error                   { return nil }
func (r *mockRows) Next(dest []driver.Value) error { return io.EOF }

func TestCrossModule_TransactionRollback(t *testing.T) {
	initDriver()
	db, err := sql.Open(mockName, "test")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// 1. Successful transaction commits
	testDrv.mu.Lock()
	testDrv.begun = 0
	testDrv.committed = 0
	testDrv.rolled = 0
	testDrv.mu.Unlock()

	err = sqltx.Run(ctx, db, nil, func(txCtx context.Context) error {
		// Core operation uses executor
		coreExec := sqltx.Executor(txCtx, db)
		if _, ok := coreExec.(*sql.Tx); !ok {
			t.Fatal("expected coreExec to join transaction")
		}

		// Plugin operation uses executor
		pluginExec := sqltx.Executor(txCtx, db)
		if pluginExec != coreExec {
			t.Fatal("expected plugin to share identical transaction instance with core")
		}

		// Nested call joins same tx
		return sqltx.Run(txCtx, db, nil, func(nestedCtx context.Context) error {
			nestedExec := sqltx.Executor(nestedCtx, db)
			if nestedExec != coreExec {
				t.Fatal("expected nested run to join same transaction")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("expected Run success, got %v", err)
	}

	testDrv.mu.Lock()
	if testDrv.begun != 1 || testDrv.committed != 1 || testDrv.rolled != 0 {
		t.Fatalf("expected 1 begin, 1 commit, 0 rollback, got b=%d c=%d r=%d",
			testDrv.begun, testDrv.committed, testDrv.rolled)
	}
	testDrv.mu.Unlock()

	// 2. Error in transaction rolls back all operations across core and plugins
	testErr := errors.New("aborted by plugin business validation")
	err = sqltx.Run(ctx, db, nil, func(txCtx context.Context) error {
		_ = sqltx.Executor(txCtx, db)
		return testErr
	})
	if !errors.Is(err, testErr) {
		t.Fatalf("expected testErr, got %v", err)
	}

	testDrv.mu.Lock()
	if testDrv.rolled != 1 {
		t.Fatalf("expected transaction rollback on error, rolled=%d", testDrv.rolled)
	}
	testDrv.mu.Unlock()
}

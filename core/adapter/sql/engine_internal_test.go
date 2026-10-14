package sqladapter

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/schema"
)

func sampleSchema() *schema.Schema {
	s := schema.New()
	_ = s.AddModel(&schema.Model{
		Name:       "users",
		TableName:  "auth_users",
		PrimaryKey: "id",
		Fields: map[string]schema.Field{
			"id": {
				Name:     "id",
				Type:     schema.TypeString,
				Required: true,
			},
			"email": {
				Name:     "email",
				Type:     schema.TypeString,
				Required: true,
				Unique:   true,
			},
			"created_at": {
				Name:     "created_at",
				DBName:   "created_time",
				Type:     schema.TypeTime,
				Required: true,
			},
		},
		Indexes: []schema.Index{
			{
				Name:   "idx_users_email",
				Fields: []string{"email"},
				Unique: true,
			},
		},
	})
	_ = s.AddModel(&schema.Model{
		Name:       "accounts",
		TableName:  "auth_accounts",
		PrimaryKey: "id",
		Fields: map[string]schema.Field{
			"id": {
				Name:     "id",
				Type:     schema.TypeString,
				Required: true,
			},
			"user_id": {
				Name:     "user_id",
				Type:     schema.TypeString,
				Required: true,
				References: &schema.Reference{
					Model:    "users",
					Field:    "id",
					OnDelete: "CASCADE",
				},
			},
		},
	})
	return s
}

func TestBaseAdapter_RegisterSchema(t *testing.T) {
	ad := New(nil, Postgres)

	if err := ad.RegisterSchema(context.Background(), nil); err == nil {
		t.Fatal("expected error registering nil schema")
	}

	invalidSchema := schema.New()
	_ = invalidSchema.AddModel(&schema.Model{
		Name:       "bad",
		TableName:  "bad",
		PrimaryKey: "id",
		Fields: map[string]schema.Field{
			"bad_field": {
				Name: "bad_field",
				Type: "unsupported_type",
			},
		},
	})
	if err := ad.RegisterSchema(context.Background(), invalidSchema); err == nil {
		t.Fatal("expected validation error for invalid schema")
	}

	validSchema := sampleSchema()
	if err := ad.RegisterSchema(context.Background(), validSchema); err != nil {
		t.Fatalf("unexpected error registering valid schema: %v", err)
	}

	// Verify cloned
	m, err := ad.getModel("users")
	if err != nil {
		t.Fatalf("expected model users to be found: %v", err)
	}
	if m.TableName != "auth_users" {
		t.Errorf("expected table name auth_users, got %s", m.TableName)
	}

	// Dynamic fallback for unregistered models
	fallback, err := ad.getModel("unknown_table")
	if err != nil {
		t.Fatalf("unexpected error on fallback model: %v", err)
	}
	if fallback.TableName != "unknown_table" {
		t.Errorf("expected fallback table name unknown_table, got %s", fallback.TableName)
	}
}

func TestBaseAdapter_DDLGeneration_Postgres(t *testing.T) {
	ad := New(nil, Postgres)
	s := sampleSchema()
	_ = ad.RegisterSchema(context.Background(), s)

	userModel, _ := s.GetModel("users")
	ddl := ad.buildCreateTableDDL(userModel)
	if !strings.HasPrefix(ddl, `CREATE TABLE IF NOT EXISTS "auth_users"`) {
		t.Errorf("unexpected postgres table DDL: %s", ddl)
	}
	if !strings.Contains(ddl, `"id" VARCHAR(255) PRIMARY KEY`) {
		t.Errorf("missing primary key in DDL: %s", ddl)
	}
	if !strings.Contains(ddl, `"email" VARCHAR(255) NOT NULL UNIQUE`) {
		t.Errorf("missing unique field in DDL: %s", ddl)
	}
	if !strings.Contains(ddl, `"created_time" TIMESTAMPTZ NOT NULL`) {
		t.Errorf("missing DBName or type in DDL: %s", ddl)
	}

	accountModel, _ := s.GetModel("accounts")
	accountDDL := ad.buildCreateTableDDL(accountModel)
	if !strings.Contains(accountDDL, `REFERENCES "auth_users"("id") ON DELETE CASCADE`) {
		t.Errorf("missing foreign key in DDL: %s", accountDDL)
	}

	idxDDL := ad.buildCreateIndexDDL("auth_users", userModel.Indexes[0])
	if idxDDL != `CREATE UNIQUE INDEX IF NOT EXISTS "idx_users_email" ON "auth_users" ("email")` {
		t.Errorf("unexpected index DDL: %s", idxDDL)
	}
}

func TestBaseAdapter_DDLGeneration_SQLite(t *testing.T) {
	ad := New(nil, SQLite)
	s := sampleSchema()
	_ = ad.RegisterSchema(context.Background(), s)

	userModel, _ := s.GetModel("users")
	ddl := ad.buildCreateTableDDL(userModel)
	if !strings.HasPrefix(ddl, `CREATE TABLE IF NOT EXISTS "auth_users"`) {
		t.Errorf("unexpected sqlite table DDL: %s", ddl)
	}
	if !strings.Contains(ddl, `"created_time" DATETIME NOT NULL`) {
		t.Errorf("missing DATETIME type in DDL: %s", ddl)
	}

	accountModel, _ := s.GetModel("accounts")
	accountDDL := ad.buildCreateTableDDL(accountModel)
	if strings.Contains(accountDDL, `REFERENCES`) {
		t.Errorf("sqlite should not contain REFERENCES in this DDL: %s", accountDDL)
	}
}

func TestBaseAdapter_DDLGeneration_MySQL(t *testing.T) {
	ad := New(nil, MySQL)
	s := sampleSchema()
	_ = ad.RegisterSchema(context.Background(), s)

	userModel, _ := s.GetModel("users")
	ddl := ad.buildCreateTableDDL(userModel)
	if !strings.HasPrefix(ddl, "CREATE TABLE IF NOT EXISTS `auth_users`") {
		t.Errorf("unexpected mysql table DDL: %s", ddl)
	}
	if !strings.Contains(ddl, "`created_time` DATETIME(6) NOT NULL") {
		t.Errorf("missing DATETIME(6) type in DDL: %s", ddl)
	}

	idxDDL := ad.buildCreateIndexDDL("auth_users", userModel.Indexes[0])
	if idxDDL != "CREATE UNIQUE INDEX IF NOT EXISTS `idx_users_email` ON `auth_users` (`email`)" {
		t.Errorf("unexpected mysql index DDL: %s", idxDDL)
	}
}

func TestBaseAdapter_ConditionBuilder(t *testing.T) {
	ad := New(nil, Postgres)
	s := sampleSchema()
	userModel, _ := s.GetModel("users")

	// 1. OpEq
	clause, args := ad.buildCondition(userModel, adapter.Eq("email", "alice@example.com"), 1)
	if clause != `"email" = $1` || len(args) != 1 || args[0] != "alice@example.com" {
		t.Errorf("unexpected Eq condition: clause=%s args=%v", clause, args)
	}

	// 2. OpEq with DBName mapping
	clause, args = ad.buildCondition(userModel, adapter.Eq("created_at", time.Time{}), 1)
	if clause != `"created_time" = $1` {
		t.Errorf("expected DBName created_time, got %s", clause)
	}

	// 3. OpIsNull / OpIsNotNull
	clause, args = ad.buildCondition(userModel, adapter.IsNull("email"), 1)
	if clause != `"email" IS NULL` || len(args) != 0 {
		t.Errorf("unexpected IsNull: %s", clause)
	}
	clause, args = ad.buildCondition(userModel, adapter.IsNotNull("email"), 1)
	if clause != `"email" IS NOT NULL` || len(args) != 0 {
		t.Errorf("unexpected IsNotNull: %s", clause)
	}

	// 4. OpIn with variadic args
	clause, args = ad.buildCondition(userModel, adapter.In("id", "u1", "u2"), 2)
	if clause != `"id" IN ($2, $3)` || len(args) != 2 {
		t.Errorf("unexpected In: clause=%s args=%v", clause, args)
	}

	// OpIn with slice
	clause, args = ad.buildCondition(userModel, adapter.In("id", []string{"u1", "u2"}), 2)
	if clause != `"id" IN ($2, $3)` || len(args) != 2 {
		t.Errorf("unexpected In with slice: clause=%s args=%v", clause, args)
	}

	// Empty In
	clause, args = ad.buildCondition(userModel, adapter.In("id"), 1)
	if clause != "1 = 0" || len(args) != 0 {
		t.Errorf("unexpected empty In: clause=%s args=%v", clause, args)
	}
}

func TestDialects_ErrorMapping(t *testing.T) {
	// ErrNoRows
	if !errors.Is(Postgres.MapError(sql.ErrNoRows), adapter.ErrNotFound) {
		t.Errorf("expected ErrNotFound for postgres ErrNoRows")
	}
	if !errors.Is(SQLite.MapError(sql.ErrNoRows), adapter.ErrNotFound) {
		t.Errorf("expected ErrNotFound for sqlite ErrNoRows")
	}
	if !errors.Is(MySQL.MapError(sql.ErrNoRows), adapter.ErrNotFound) {
		t.Errorf("expected ErrNotFound for mysql ErrNoRows")
	}

	// Conflicts
	pgErr := errors.New("ERROR: duplicate key value violates unique constraint 23505")
	if !errors.Is(Postgres.MapError(pgErr), adapter.ErrConflict) {
		t.Errorf("expected ErrConflict for postgres 23505: %v", Postgres.MapError(pgErr))
	}

	sqliteErr := errors.New("UNIQUE constraint failed: auth_users.email")
	if !errors.Is(SQLite.MapError(sqliteErr), adapter.ErrConflict) {
		t.Errorf("expected ErrConflict for sqlite constraint: %v", SQLite.MapError(sqliteErr))
	}

	mysqlErr := errors.New("Error 1062 (23000): Duplicate entry 'test' for key 'email'")
	if !errors.Is(MySQL.MapError(mysqlErr), adapter.ErrConflict) {
		t.Errorf("expected ErrConflict for mysql 1062: %v", MySQL.MapError(mysqlErr))
	}

	// Nil error
	if Postgres.MapError(nil) != nil {
		t.Errorf("expected nil error on nil input")
	}

	// Unrelated error
	otherErr := errors.New("connection reset by peer")
	if Postgres.MapError(otherErr) != otherErr {
		t.Errorf("expected unchanged error for unrelated error")
	}
}

// --- In-Memory Driver Mock for database/sql ---

type mockDriver struct {
	mu      sync.Mutex
	queries []string
	rows    map[string][]map[string]any
}

func (d *mockDriver) Open(name string) (driver.Conn, error) {
	return &mockConn{d: d}, nil
}

type mockConn struct {
	d *mockDriver
}

func (c *mockConn) Prepare(query string) (driver.Stmt, error) {
	return &mockStmt{c: c, query: query}, nil
}

func (c *mockConn) Close() error { return nil }

func (c *mockConn) Begin() (driver.Tx, error) {
	return &mockTx{}, nil
}

type mockTx struct{}

func (t *mockTx) Commit() error   { return nil }
func (t *mockTx) Rollback() error { return nil }

type mockStmt struct {
	c     *mockConn
	query string
}

func (s *mockStmt) Close() error { return nil }

func (s *mockStmt) NumInput() int { return -1 }

func (s *mockStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.c.d.mu.Lock()
	defer s.c.d.mu.Unlock()
	s.c.d.queries = append(s.c.d.queries, s.query)
	return driver.RowsAffected(1), nil
}

func (s *mockStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.c.d.mu.Lock()
	defer s.c.d.mu.Unlock()
	s.c.d.queries = append(s.c.d.queries, s.query)

	if strings.Contains(s.query, "COUNT(*)") {
		return &mockRows{
			columns: []string{"count"},
			data:    [][]driver.Value{{int64(42)}},
		}, nil
	}

	return &mockRows{
		columns: []string{"id", "email"},
		data: [][]driver.Value{
			{"u-1", "user1@example.com"},
		},
	}, nil
}

type mockRows struct {
	columns []string
	data    [][]driver.Value
	idx     int
}

func (r *mockRows) Columns() []string { return r.columns }

func (r *mockRows) Close() error { return nil }

func (r *mockRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.data) {
		return io.EOF
	}
	for i, v := range r.data[r.idx] {
		dest[i] = v
	}
	r.idx++
	return nil
}

var (
	mockDriverOnce sync.Once
	testDriver     = &mockDriver{
		rows: make(map[string][]map[string]any),
	}
)

func initMockDB(t *testing.T) *sql.DB {
	mockDriverOnce.Do(func() {
		sql.Register("mock_sql_driver", testDriver)
	})
	db, err := sql.Open("mock_sql_driver", "mock_dsn")
	if err != nil {
		t.Fatalf("failed to open mock db: %v", err)
	}
	return db
}

func TestBaseAdapter_CRUDAndTransactionWithMockDB(t *testing.T) {
	db := initMockDB(t)
	defer db.Close()

	ba := New(db, Postgres)
	if ba.DB() != db {
		t.Fatal("expected DB() to match injected db")
	}
	if ba.Dialect() != Postgres {
		t.Fatal("expected Dialect() to match Postgres")
	}

	ctx := context.Background()

	// 1. Migrate with schema
	s := sampleSchema()
	if err := ba.RegisterSchema(ctx, s); err != nil {
		t.Fatalf("RegisterSchema failed: %v", err)
	}
	if err := ba.Migrate(ctx); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// 2. Create
	createData := map[string]any{
		"id":         "user-123",
		"email":      "test@example.com",
		"created_at": time.Now(),
	}
	created, err := ba.Create(ctx, "users", createData)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if created["id"] != "user-123" {
		t.Fatalf("expected id user-123, got %v", created["id"])
	}

	// 3. FindOne & FindMany
	one, err := ba.FindOne(ctx, "users", []adapter.Condition{adapter.Eq("id", "u-1")})
	if err != nil {
		t.Fatalf("FindOne failed: %v", err)
	}
	if one["id"] != "u-1" {
		t.Errorf("expected id u-1, got %v", one["id"])
	}

	many, err := ba.FindMany(ctx, adapter.Query{
		Model:  "users",
		Where:  []adapter.Condition{adapter.Eq("email", "user1@example.com")},
		SortBy: "email",
		Desc:   true,
		Limit:  10,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("FindMany failed: %v", err)
	}
	if len(many) != 1 {
		t.Fatalf("expected 1 record from FindMany, got %d", len(many))
	}

	// 4. Update
	affected, err := ba.Update(ctx, "users", []adapter.Condition{adapter.Eq("id", "u-1")}, map[string]any{
		"email": "updated@example.com",
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if affected != 1 {
		t.Errorf("expected 1 row affected, got %d", affected)
	}

	// Empty update returns 0
	affEmpty, err := ba.Update(ctx, "users", nil, map[string]any{})
	if err != nil || affEmpty != 0 {
		t.Errorf("expected 0 affected on empty update")
	}

	// 5. Delete
	deleted, err := ba.Delete(ctx, "users", []adapter.Condition{adapter.Eq("id", "u-1")})
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	// 6. Count
	count, err := ba.Count(ctx, "users", []adapter.Condition{adapter.Eq("email", "test@example.com")})
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 42 {
		t.Errorf("expected count 42, got %d", count)
	}

	// 7. Transaction
	err = ba.Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		_, txErr := tx.Create(txCtx, "users", createData)
		return txErr
	})
	if err != nil {
		t.Fatalf("Transaction failed: %v", err)
	}
}

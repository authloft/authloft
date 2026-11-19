package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun/driver/pgdriver"
)

// myTestErr 构造 MariaDB 服务端错误（离线：错误对象可脱离实库构造）。
func myTestErr(number uint16) error {
	return &mysqldriver.MySQLError{Number: number, Message: "test mysql error"}
}

// pgTestErr 构造带 SQLSTATE 的 PG 错误（pgdriver.Error 的测试期构造出口）。
func pgTestErr(code string) error {
	return pgdriver.NewError(map[byte]string{'C': code, 'M': "test pg error " + code})
}

func TestIsDuplicateKey(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"mysql dup entry", myTestErr(1062), true},
		{"mysql wrapped", fmt.Errorf("insert: %w", myTestErr(1062)), true},
		{"pg unique violation", pgTestErr("23505"), true},
		{"pg wrapped", fmt.Errorf("insert: %w", pgTestErr("23505")), true},
		{"mysql other code", myTestErr(1213), false},
		{"pg fk violation not dup", pgTestErr("23503"), false},
		{"pg check violation not dup", pgTestErr("23514"), false},
		{"no rows", sql.ErrNoRows, false},
		{"ctx canceled", context.Canceled, false},
		{"generic", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsDuplicateKey(tc.err); got != tc.want {
				t.Fatalf("IsDuplicateKey(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsDeadlock(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"mysql deadlock", myTestErr(1213), true},
		{"mysql wrapped", fmt.Errorf("upsert: %w", myTestErr(1213)), true},
		{"pg deadlock detected", pgTestErr("40P01"), true},
		{"pg wrapped", fmt.Errorf("upsert: %w", pgTestErr("40P01")), true},
		{"mysql other code", myTestErr(1062), false},
		{"pg lock timeout not deadlock", pgTestErr("55P03"), false},
		{"no rows", sql.ErrNoRows, false},
		{"generic", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsDeadlock(tc.err); got != tc.want {
				t.Fatalf("IsDeadlock(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsNoSuchTable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"mysql no such table", myTestErr(1146), true},
		{"mysql wrapped", fmt.Errorf("query: %w", myTestErr(1146)), true},
		{"pg undefined table", pgTestErr("42P01"), true},
		{"pg wrapped", fmt.Errorf("query: %w", pgTestErr("42P01")), true},
		{"mysql other code", myTestErr(1050), false},
		{"pg syntax error not no-such-table", pgTestErr("42601"), false},
		{"no rows", sql.ErrNoRows, false},
		{"generic", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNoSuchTable(tc.err); got != tc.want {
				t.Fatalf("IsNoSuchTable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

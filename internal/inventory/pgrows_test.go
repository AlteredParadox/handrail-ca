// handrail-ca — a lightweight web UI for step-ca.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package inventory

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rowServer answers the queries handrail-ca makes of the CA's database with
// rows chosen by the test, over PostgreSQL's simple query protocol: each
// row is the text of its columns, as the server would send them, and
// answer picks the rows by the query's text.
func rowServer(t *testing.T, answer func(query string) (columns []string, rows [][]string)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveRows(conn, answer)
		}
	}()
	return ln.Addr().String()
}

func serveRows(conn net.Conn, answer func(string) ([]string, [][]string)) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	be := pgproto3.NewBackend(conn, conn)
	if _, err := be.ReceiveStartupMessage(); err != nil {
		return
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if be.Flush() != nil {
		return
	}
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		q, ok := msg.(*pgproto3.Query)
		if !ok {
			return // Terminate, or something this does not speak
		}
		columns, rows := answer(q.String)
		fields := make([]pgproto3.FieldDescription, len(columns))
		for i, c := range columns {
			oid := uint32(17) // bytea
			if c == "bool" {
				oid = 16
			}
			fields[i] = pgproto3.FieldDescription{Name: []byte("c"), DataTypeOID: oid, DataTypeSize: -1, TypeModifier: -1}
		}
		be.Send(&pgproto3.RowDescription{Fields: fields})
		for _, row := range rows {
			values := make([][]byte, len(row))
			for i, v := range row {
				if v != "NULL" {
					values[i] = []byte(v)
				}
			}
			be.Send(&pgproto3.DataRow{Values: values})
		}
		be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT")})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		if be.Flush() != nil {
			return
		}
	}
}

// bytea is a value as PostgreSQL writes a bytea in text.
func bytea(s string) string { return `\x` + hex.EncodeToString([]byte(s)) }

// The queries' rows as the driver hands them over: keys taken, and a key
// the query flags as too long fails the read, naming the table and not
// repeating anything of the row.
func TestTheQueriesTakeKeysAndRefuseFlaggedOnes(t *testing.T) {
	clearPGEnv(t)
	flagged := map[string]bool{}
	addr := rowServer(t, func(q string) ([]string, [][]string) {
		if strings.Contains(q, "revoked_x509_certs") {
			rows := [][]string{{bytea("1001"), "f", bytea(`{"Serial":"1001"}`)}}
			if flagged["revoked"] {
				rows = append(rows, []string{"NULL", "t", "NULL"})
			}
			return []string{"bytea", "bool", "bytea"}, rows
		}
		rows := [][]string{{bytea("1001"), "f"}, {bytea("1002"), "f"}}
		if flagged["certs"] {
			rows = append(rows, []string{"NULL", "t"})
		}
		return []string{"bytea", "bool"}, rows
	})
	p, err := openPostgres("postgres://handrail:"+testPassword+"@"+addr+"/stepca?sslmode=disable", nil, func(c *pgxpool.Config) {
		c.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serials, err := p.Serials(ctx)
	if err != nil || strings.Join(serials, ",") != "1001,1002" {
		t.Fatalf("Serials = %v, %v", serials, err)
	}
	revoked, err := p.Revocations(ctx)
	if err != nil || len(revoked) != 1 || revoked[0].Serial != "1001" || string(revoked[0].JSON) != `{"Serial":"1001"}` {
		t.Fatalf("Revocations = %+v, %v", revoked, err)
	}

	flagged["certs"], flagged["revoked"] = true, true
	if _, err := p.Serials(ctx); err == nil || !strings.Contains(err.Error(), "a row of x509_certs has a key of more than") {
		t.Errorf("Serials with a flagged row: %v", err)
	}
	if _, err := p.Revocations(ctx); err == nil || !strings.Contains(err.Error(), "a row of revoked_x509_certs has a key of more than") {
		t.Errorf("Revocations with a flagged row: %v", err)
	}
}

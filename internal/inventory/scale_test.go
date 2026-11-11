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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestScale measures the inventory against a large CA database: how long
// the first read takes, how long a read takes once everything is known,
// how much memory the picture holds, and how long the list's queries take.
// The plan (docs/PLAN.md, section 6) records what it found.
//
// It writes synthetic certificate rows into the development CA's database
// (deploy/dev) as that database's owner, until the table holds the number
// asked for, and leaves them there: `make dev-down` removes them with the
// rest. It never runs by itself: `make dev-measure` names the row count and
// the two connection strings. It is not a pass-or-fail test of speed; it
// fails only if something does not work.
func TestScale(t *testing.T) {
	want, _ := strconv.Atoi(os.Getenv("HANDRAIL_DEV_SCALE_ROWS"))
	ownerFile, readerFile := os.Getenv("HANDRAIL_DEV_DB_OWNER_URL_FILE"), os.Getenv("HANDRAIL_DEV_DB_URL_FILE")
	if want <= 0 || ownerFile == "" || readerFile == "" {
		t.Skip("not asked to measure: run `make dev-up` and `make dev-measure`")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	owner, err := os.ReadFile(ownerFile)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, strings.TrimSpace(string(owner)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var have int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM x509_certs`).Scan(&have); err != nil {
		t.Fatal(err)
	}
	if have < want {
		start := time.Now()
		fillSynthetic(ctx, t, conn, want-have)
		t.Logf("wrote %d synthetic rows in %s", want-have, time.Since(start).Round(time.Millisecond))
	}
	var rows, bytes int64
	if err := conn.QueryRow(ctx, `SELECT count(*), COALESCE(sum(octet_length(nvalue)), 0) FROM x509_certs`).Scan(&rows, &bytes); err != nil {
		t.Fatal(err)
	}

	reader, err := os.ReadFile(readerFile)
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenPostgres(string(reader), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	heap := func() uint64 {
		var m runtime.MemStats
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	timed := func(f func()) time.Duration {
		start := time.Now()
		f()
		return time.Since(start)
	}
	refresh := func(inv *Inventory) {
		if err := inv.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}

	before := heap()
	inv := New(db)
	first := timed(func() { refresh(inv) })
	held := heap() - before
	var peak runtime.MemStats
	runtime.ReadMemStats(&peak)

	// Nothing new: what every later round costs.
	var again []time.Duration
	for range 5 {
		again = append(again, timed(func() { refresh(inv) }))
	}
	// A busy half minute: a hundred certificates issued since the last read.
	fillSynthetic(ctx, t, conn, 100)
	withNew := timed(func() { refresh(inv) })

	snap := inv.Snapshot()
	now := time.Now()
	counts := snap.Counts(now)
	t.Logf("database: %d certificate rows, %.1f MB of certificates", rows, float64(bytes)/1e6)
	t.Logf("picture: %d certificates (%d valid, %d expiring, %d expired, %d revoked)",
		len(snap.Certificates), counts[StatusValid], counts[StatusExpiring], counts[StatusExpired], counts[StatusRevoked])
	t.Logf("first read: %s", first.Round(time.Millisecond))
	t.Logf("read again, nothing new (median of 5): %s", median(again).Round(time.Millisecond))
	t.Logf("read again, 100 new certificates: %s", withNew.Round(time.Millisecond))
	t.Logf("memory held by the picture: %.1f MB (%.0f bytes a certificate); Go heap in use at the end %.1f MB, obtained from the system %.1f MB",
		float64(held)/1e6, float64(held)/float64(len(snap.Certificates)), float64(peak.HeapInuse)/1e6, float64(peak.Sys)/1e6)

	// The list's queries, each as one page request runs it.
	some := snap.Certificates[len(snap.Certificates)/2]
	for _, q := range []struct {
		name  string
		query Query
	}{
		{"default list (active, by expiry)", Query{View: ViewActive, Order: ByExpiry}},
		{"everything, by subject", Query{View: ViewAll, Order: BySubject, IncludeAdmin: true}},
		{"everything, by date issued", Query{View: ViewAll, Order: ByIssued, IncludeAdmin: true}},
		{"search for one name", Query{View: ViewAll, Search: some.Subject}},
		{"search for one serial", Query{View: ViewAll, Search: some.SerialHex}},
		{"search that matches many", Query{View: ViewAll, Search: "team07"}},
		{"one provisioner", Query{View: ViewAll, Provisioner: "handrail"}},
	} {
		var took []time.Duration
		var res Result
		for range 5 {
			took = append(took, timed(func() { res = snap.Select(q.query, now) }))
		}
		t.Logf("query, %s: %s for %d rows", q.name, median(took).Round(100*time.Microsecond), len(res.Rows))
	}
	var ders []time.Duration
	for i := range 5 {
		c := snap.Certificates[(i+1)*len(snap.Certificates)/7]
		ders = append(ders, timed(func() {
			if _, err := inv.DER(ctx, c.Serial); err != nil {
				t.Fatal(err)
			}
		}))
	}
	t.Logf("one certificate for its page (median of 5): %s", median(ders).Round(100*time.Microsecond))
	runtime.KeepAlive(inv)
}

func median(d []time.Duration) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[len(d)/2]
}

// fillSynthetic writes n certificate rows as step-ca stores them: the
// certificate under its decimal serial, what the CA recorded about its
// provisioner beside it, and a revocation for one in fifty. The serials are
// random 128-bit numbers, as step-ca's are; the names, lifetimes and
// provisioners are mixed so that the picture is not unrealistically uniform.
func fillSynthetic(ctx context.Context, t *testing.T, conn *pgx.Conn, n int) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &x509.Certificate{Subject: pkix.Name{CommonName: "Synthetic Intermediate CA"}}
	provisioners := []Provisioner{
		{ID: "synthetic-acme", Name: "acme", Type: "ACME"}, {ID: "synthetic-acme", Name: "acme", Type: "ACME"},
		{ID: "synthetic-handrail", Name: "handrail", Type: "JWK"},
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	type row struct {
		serial            string
		der, data, revoke []byte
	}
	make1 := func(i int) (row, error) {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return row{}, err
		}
		name := fmt.Sprintf("svc%06d.team%02d.bulk.handrail.test", i, i%70)
		tmpl := &x509.Certificate{
			SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		if i%5 == 0 {
			tmpl.DNSNames = append(tmpl.DNSNames, fmt.Sprintf("svc%06d.bulk.handrail.test", i))
		}
		if i%10 == 0 {
			tmpl.IPAddresses = []net.IP{net.IPv4(10, 20, byte(i>>8), byte(i))}
		}
		// Six in ten have expired, as on a CA that issues short-lived
		// certificates; the rest are in date, a few near their end.
		day := 24 * time.Hour
		switch age := time.Duration(i%1000) * time.Hour; {
		case i%10 < 6:
			tmpl.NotBefore, tmpl.NotAfter = now.Add(-age-30*day), now.Add(-age-time.Hour)
		case i%10 == 6:
			tmpl.NotBefore, tmpl.NotAfter = now.Add(-80*day), now.Add(10*day-age/100)
		default:
			tmpl.NotBefore, tmpl.NotAfter = now.Add(-age), now.Add(90*day-age)
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &leafKey.PublicKey, caKey)
		if err != nil {
			return row{}, err
		}
		p := provisioners[i%len(provisioners)]
		data, err := json.Marshal(map[string]any{"provisioner": map[string]string{"id": p.ID, "name": p.Name, "type": p.Type}})
		if err != nil {
			return row{}, err
		}
		r := row{serial: serial.String(), der: der, data: data}
		if i%50 == 7 {
			r.revoke, err = json.Marshal(map[string]any{
				"Serial": r.serial, "ProvisionerID": p.ID, "ReasonCode": 4, "Reason": "synthetic",
				"RevokedAt": now.Add(-time.Hour), "ExpiresAt": tmpl.NotAfter, "TokenID": "", "MTLS": false, "ACME": p.Type == "ACME",
			})
			if err != nil {
				return row{}, err
			}
		}
		return r, nil
	}

	const batch = 5000
	for done := 0; done < n; done += batch {
		size := min(batch, n-done)
		made := make([]row, size)
		errs := make([]error, size)
		var wg sync.WaitGroup
		workers := runtime.GOMAXPROCS(0)
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := w; j < size; j += workers {
					made[j], errs[j] = make1(done + j)
				}
			}()
		}
		wg.Wait()
		var certs, datas, revocations [][]any
		for j, r := range made {
			if errs[j] != nil {
				t.Fatal(errs[j])
			}
			key := []byte(r.serial)
			certs = append(certs, []any{key, r.der})
			datas = append(datas, []any{key, r.data})
			if r.revoke != nil {
				revocations = append(revocations, []any{key, r.revoke})
			}
		}
		for table, rows := range map[string][][]any{"x509_certs": certs, "x509_certs_data": datas, "revoked_x509_certs": revocations} {
			if _, err := conn.CopyFrom(ctx, pgx.Identifier{table}, []string{"nkey", "nvalue"}, pgx.CopyFromRows(rows)); err != nil {
				t.Fatalf("writing %s: %v", table, err)
			}
		}
	}
}

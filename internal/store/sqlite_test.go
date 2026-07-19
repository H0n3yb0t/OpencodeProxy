package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenMigratesClientIdentityColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`
CREATE TABLE proxy_requests (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  final_key_id INTEGER,
  model TEXT NOT NULL DEFAULT ''
);
INSERT INTO proxy_requests(id,started_at,model) VALUES('legacy-request','2026-01-01T00:00:00Z','legacy-model');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var clientID, clientName string
	if err := db.db.QueryRow(`SELECT client_id,client_name FROM proxy_requests WHERE id='legacy-request'`).Scan(&clientID, &clientName); err != nil {
		t.Fatal(err)
	}
	if clientID != "master" || clientName != "主访问密钥" {
		t.Fatalf("unexpected migrated identity: %q %q", clientID, clientName)
	}
}

func TestDashboardRoundsFractionalAverageLatency(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "dashboard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key, err := db.CreateKey(t.Context(), Key{
		Name: "key-1", EncryptedKey: []byte("ciphertext"), Fingerprint: "fingerprint-1",
		Priority: 1, AdminEnabled: true, AuthState: "valid", QuotaState: "available", ControlState: "reachable",
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, latency := range []int64{9461, 9462} {
		started := time.Now().UTC().Add(time.Duration(index) * time.Millisecond)
		record := RequestRecord{ID: "request-" + string(rune('a'+index)), StartedAt: started, Protocol: "openai", Model: "mimo-v2.5"}
		if err := db.BeginRequest(t.Context(), record); err != nil {
			t.Fatal(err)
		}
		finished := started.Add(time.Duration(latency) * time.Millisecond)
		record.FinishedAt = &finished
		record.FinalKeyID = &key.ID
		record.AttemptCount = 1
		record.HTTPStatus = 200
		record.Outcome = "success"
		record.LatencyMS = latency
		if err := db.FinishRequest(t.Context(), record, Usage{State: "complete"}); err != nil {
			t.Fatal(err)
		}
	}
	dashboard, err := db.Dashboard(t.Context(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(dashboard.ByKey) != 1 || dashboard.ByKey[0].AvgLatencyMS != 9462 {
		t.Fatalf("unexpected key aggregates: %#v", dashboard.ByKey)
	}
}

package proxy

import (
	"net/http"
	"testing"
	"time"
)

func TestClassifyQuotaAndReset(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	c := Classify(429, http.Header{}, []byte(`{"error":{"message":"5 hour usage limit reached. It will reset in 2 hours 16 minutes."}}`), now)
	if c.Kind != ErrorQuota || c.Window != "5h" {
		t.Fatalf("unexpected classification: %#v", c)
	}
	want := now.Add(2*time.Hour + 16*time.Minute)
	if c.ResetAt == nil || !c.ResetAt.Equal(want) {
		t.Fatalf("reset=%v want=%v", c.ResetAt, want)
	}
}

func TestClassifyDoesNotTreatEvery401AsAuth(t *testing.T) {
	c := Classify(401, http.Header{}, []byte(`{"error":"weekly/monthly limit exhausted"}`), time.Now())
	if c.Kind != ErrorQuota {
		t.Fatalf("kind=%s", c.Kind)
	}
}

func TestParseAnthropicUsage(t *testing.T) {
	a := newUsageAccumulator("anthropic")
	a.ObserveJSON([]byte(`{"usage":{"input_tokens":100,"cache_read_input_tokens":80,"cache_creation_input_tokens":20,"output_tokens":12}}`))
	u := a.Usage()
	if value(u.TotalInput) != 200 || value(u.CacheRead) != 80 || value(u.OutputTokens) != 12 || u.State != "complete" {
		t.Fatalf("unexpected usage: %#v", u)
	}
}

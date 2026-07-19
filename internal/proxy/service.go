package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/local/opencode-keypool/internal/config"
	"github.com/local/opencode-keypool/internal/cryptox"
	"github.com/local/opencode-keypool/internal/store"
)

type Service struct {
	cfg    config.Config
	store  *store.Store
	cipher *cryptox.Cipher
	client *http.Client
	mu     sync.Mutex
	probe  sync.Mutex
}

func NewService(cfg config.Config, db *store.Store, cipher *cryptox.Cipher) *Service {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 32
	transport.IdleConnTimeout = cfg.IdleTimeout
	return &Service{cfg: cfg, store: db, cipher: cipher, client: &http.Client{Transport: transport, Timeout: cfg.RequestTimeout}}
}

type requestMeta struct {
	Model        string
	Stream       bool
	MessageCount int
	ToolCount    int
}

func (s *Service) HandleInference(protocol string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		started := time.Now().UTC()
		requestID := newID()
		w.Header().Set("X-Keypool-Request-Id", requestID)
		body, err := readLimited(r.Body, s.cfg.MaxRequestBytes)
		if err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": map[string]any{"message": err.Error(), "type": "request_too_large"}})
			return
		}
		meta := inspectRequest(body)
		settings, _ := s.store.GetSettings(r.Context())
		if protocol == "openai" && meta.Stream && settings.ForceStreamUsage {
			body = ensureStreamUsage(body)
		}
		record := store.RequestRecord{ID: requestID, StartedAt: started, Protocol: protocol, Model: meta.Model, Stream: meta.Stream, RequestBytes: int64(len(body)), MessageCount: meta.MessageCount, ToolCount: meta.ToolCount}
		if err := s.store.BeginRequest(r.Context(), record); err != nil {
			slog.Error("begin request telemetry", "error", err)
		}

		// Serializing only selection/state transitions prevents a burst of requests
		// from promoting several standby keys at once. Network work remains concurrent.
		s.mu.Lock()
		_ = s.store.MarkHalfOpenDue(r.Context())
		keys, err := s.store.EligibleKeys(r.Context())
		s.mu.Unlock()
		if err != nil || len(keys) == 0 {
			s.finishUnavailable(r.Context(), &record, started, "no_available_key")
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{"message": "No inference key is currently available", "type": "keypool_unavailable"}})
			return
		}

		var lastStatus int
		var lastHeader http.Header
		var lastBody []byte
		var lastClass Classification
		for index, key := range keys {
			attemptNo := index + 1
			attemptStart := time.Now().UTC()
			secret, err := s.cipher.Decrypt(key.EncryptedKey)
			if err != nil {
				slog.Error("decrypt key", "key_id", key.ID, "error", err)
				continue
			}
			resp, err := s.callUpstream(r.Context(), r, protocol, body, secret)
			if err != nil {
				finished := time.Now().UTC()
				_ = s.store.AddAttempt(r.Context(), store.AttemptRecord{RequestID: requestID, KeyID: key.ID, AttemptNo: attemptNo, StartedAt: attemptStart, FinishedAt: finished, Outcome: "error", ErrorClass: string(ErrorNetwork), LatencyMS: finished.Sub(attemptStart).Milliseconds()})
				record.FinalKeyID = &key.ID
				record.AttemptCount = attemptNo
				record.HTTPStatus = http.StatusBadGateway
				record.Outcome = "error"
				record.ErrorClass = string(ErrorNetwork)
				s.finish(r.Context(), &record, store.Usage{State: "unavailable"}, started)
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": map[string]any{"message": "OpenCode upstream request failed", "type": "upstream_network_error"}})
				return
			}
			upstreamReqID := resp.Header.Get("X-Request-Id")
			if meta.Stream && resp.StatusCode >= 200 && resp.StatusCode < 300 && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
				streamResult := s.forwardStream(w, resp, protocol, started)
				finished := time.Now().UTC()
				if streamResult.firstError != nil && (streamResult.firstError.Kind == ErrorQuota || streamResult.firstError.Kind == ErrorAuth) {
					resp.Body.Close()
					_ = s.recordKeyFailure(r.Context(), key.ID, *streamResult.firstError, finished)
					_ = s.store.AddAttempt(r.Context(), store.AttemptRecord{RequestID: requestID, KeyID: key.ID, AttemptNo: attemptNo, StartedAt: attemptStart, FinishedAt: finished, HTTPStatus: http.StatusTooManyRequests, Outcome: "failover", ErrorClass: string(streamResult.firstError.Kind), UpstreamRequest: upstreamReqID, LatencyMS: finished.Sub(attemptStart).Milliseconds()})
					lastStatus, lastBody, lastClass = http.StatusTooManyRequests, streamResult.firstEvent, *streamResult.firstError
					record.FinalKeyID = &key.ID
					continue
				}
				if streamResult.lateError != nil {
					_ = s.recordKeyFailure(r.Context(), key.ID, *streamResult.lateError, finished)
				} else {
					_ = s.store.MarkUsed(r.Context(), key.ID)
					s.promoteIfNeeded(r.Context(), key)
				}
				outcome, errorClass := "success", ""
				if streamResult.copyErr != nil {
					outcome, errorClass = "error", string(ErrorNetwork)
				}
				if streamResult.lateError != nil {
					outcome, errorClass = "error", string(streamResult.lateError.Kind)
				}
				_ = s.store.AddAttempt(r.Context(), store.AttemptRecord{RequestID: requestID, KeyID: key.ID, AttemptNo: attemptNo, StartedAt: attemptStart, FinishedAt: finished, HTTPStatus: resp.StatusCode, Outcome: outcome, ErrorClass: errorClass, UpstreamRequest: upstreamReqID, LatencyMS: finished.Sub(attemptStart).Milliseconds()})
				record.FinalKeyID = &key.ID
				record.AttemptCount = attemptNo
				record.HTTPStatus = resp.StatusCode
				record.Outcome = outcome
				record.ErrorClass = errorClass
				record.TTFTMS = streamResult.ttft
				s.finish(r.Context(), &record, streamResult.usage, started)
				return
			}

			responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
			resp.Body.Close()
			finished := time.Now().UTC()
			if readErr != nil {
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": map[string]any{"message": "Could not read OpenCode response", "type": "upstream_read_error"}})
				return
			}
			classification := Classify(resp.StatusCode, resp.Header, responseBody, finished)
			if classification.Kind == ErrorQuota || classification.Kind == ErrorAuth {
				_ = s.recordKeyFailure(r.Context(), key.ID, classification, finished)
				_ = s.store.AddAttempt(r.Context(), store.AttemptRecord{RequestID: requestID, KeyID: key.ID, AttemptNo: attemptNo, StartedAt: attemptStart, FinishedAt: finished, HTTPStatus: resp.StatusCode, Outcome: "failover", ErrorClass: string(classification.Kind), UpstreamRequest: upstreamReqID, LatencyMS: finished.Sub(attemptStart).Milliseconds()})
				lastStatus, lastHeader, lastBody, lastClass = resp.StatusCode, resp.Header.Clone(), responseBody, classification
				record.FinalKeyID = &key.ID
				continue
			}

			usage := newUsageAccumulator(protocol)
			usage.ObserveJSON(responseBody)
			outcome := "success"
			if resp.StatusCode >= 400 {
				outcome = "error"
			}
			_ = s.store.AddAttempt(r.Context(), store.AttemptRecord{RequestID: requestID, KeyID: key.ID, AttemptNo: attemptNo, StartedAt: attemptStart, FinishedAt: finished, HTTPStatus: resp.StatusCode, Outcome: outcome, ErrorClass: string(classification.Kind), UpstreamRequest: upstreamReqID, LatencyMS: finished.Sub(attemptStart).Milliseconds()})
			if resp.StatusCode < 400 {
				_ = s.store.MarkUsed(r.Context(), key.ID)
				s.promoteIfNeeded(r.Context(), key)
			}
			record.FinalKeyID = &key.ID
			record.AttemptCount = attemptNo
			record.HTTPStatus = resp.StatusCode
			record.Outcome = outcome
			record.ErrorClass = string(classification.Kind)
			s.finish(r.Context(), &record, usage.Usage(), started)
			copyResponseHeaders(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(responseBody)
			return
		}

		if lastStatus == 0 {
			lastStatus = http.StatusServiceUnavailable
		}
		if lastHeader != nil {
			copyResponseHeaders(w.Header(), lastHeader)
		}
		record.AttemptCount = len(keys)
		record.HTTPStatus = lastStatus
		record.Outcome = "error"
		record.ErrorClass = string(lastClass.Kind)
		s.finish(r.Context(), &record, store.Usage{State: "unavailable"}, started)
		w.WriteHeader(lastStatus)
		if len(lastBody) > 0 {
			_, _ = w.Write(lastBody)
		} else {
			_, _ = w.Write([]byte(`{"error":{"message":"All inference keys are unavailable","type":"keypool_unavailable"}}`))
		}
	}
}

func (s *Service) callUpstream(ctx context.Context, incoming *http.Request, protocol string, body []byte, secret string) (*http.Response, error) {
	endpoint := "/chat/completions"
	if protocol == "anthropic" {
		endpoint = "/messages"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.cfg.UpstreamBaseURL, "/")+endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	copyRequestHeaders(req.Header, incoming.Header)
	req.Header.Set("Authorization", "Bearer "+secret)
	if protocol == "anthropic" {
		req.Header.Set("X-Api-Key", secret)
	}
	req.URL.RawQuery = incoming.URL.RawQuery
	req.Header.Set("Content-Type", "application/json")
	return s.client.Do(req)
}

type streamForwardResult struct {
	usage      store.Usage
	ttft       *int64
	firstError *Classification
	lateError  *Classification
	firstEvent []byte
	copyErr    error
}

func (s *Service) forwardStream(w http.ResponseWriter, resp *http.Response, protocol string, started time.Time) streamForwardResult {
	defer resp.Body.Close()
	reader := bufio.NewReaderSize(resp.Body, 64<<10)
	firstEvent, err := readSSEEvent(reader, 2<<20)
	if err != nil && !errors.Is(err, io.EOF) {
		return streamForwardResult{usage: store.Usage{State: "unavailable"}, copyErr: err}
	}
	data := eventData(firstEvent)
	if len(data) > 0 {
		classification := Classify(resp.StatusCode, resp.Header, data, time.Now().UTC())
		if classification.Kind == ErrorQuota || classification.Kind == ErrorAuth {
			return streamForwardResult{usage: store.Usage{State: "unavailable"}, firstError: &classification, firstEvent: data}
		}
	}
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	acc := newUsageAccumulator(protocol)
	var lateError *Classification
	if len(data) > 0 {
		acc.ObserveJSON(data)
	}
	var ttft *int64
	if len(firstEvent) > 0 {
		ms := time.Since(started).Milliseconds()
		ttft = &ms
		_, err = w.Write(firstEvent)
		if flusher != nil {
			flusher.Flush()
		}
		if err != nil {
			return streamForwardResult{usage: acc.Usage(), ttft: ttft, lateError: lateError, copyErr: err}
		}
	}
	for {
		event, readErr := readSSEEvent(reader, 2<<20)
		if len(event) > 0 {
			if d := eventData(event); len(d) > 0 {
				acc.ObserveJSON(d)
				classification := Classify(resp.StatusCode, resp.Header, d, time.Now().UTC())
				if classification.Kind == ErrorQuota || classification.Kind == ErrorAuth {
					result := classification
					lateError = &result
					// The event is still forwarded. It is too late to replay safely,
					// but subsequent requests must not select this key.
				}
			}
			if _, err = w.Write(event); err != nil {
				return streamForwardResult{usage: acc.Usage(), ttft: ttft, lateError: lateError, copyErr: err}
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				readErr = nil
			}
			return streamForwardResult{usage: acc.Usage(), ttft: ttft, lateError: lateError, copyErr: readErr}
		}
	}
}

func readSSEEvent(r *bufio.Reader, max int) ([]byte, error) {
	var buf bytes.Buffer
	for buf.Len() <= max {
		line, err := r.ReadBytes('\n')
		buf.Write(line)
		if bytes.Equal(line, []byte("\n")) || bytes.Equal(line, []byte("\r\n")) {
			return buf.Bytes(), err
		}
		if err != nil {
			return buf.Bytes(), err
		}
	}
	return nil, fmt.Errorf("SSE event exceeds %d bytes", max)
}

func eventData(event []byte) []byte {
	var parts []string
	for _, line := range strings.Split(string(event), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "data:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if value != "" && value != "[DONE]" {
				parts = append(parts, value)
			}
		}
	}
	return []byte(strings.Join(parts, "\n"))
}

func (s *Service) HandleModels(w http.ResponseWriter, r *http.Request) {
	settings, _ := s.store.GetSettings(r.Context())
	if cached, fetched, err := s.store.ModelCache(r.Context()); err == nil && time.Since(fetched) < time.Duration(settings.ModelsCacheSec)*time.Second {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Keypool-Models-Cache", "hit")
		_, _ = w.Write(cached)
		return
	}
	keys, err := s.store.AuthValidKeys(r.Context())
	if err == nil {
		for _, key := range keys {
			secret, decErr := s.cipher.Decrypt(key.EncryptedKey)
			if decErr != nil {
				continue
			}
			req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, strings.TrimRight(s.cfg.UpstreamBaseURL, "/")+"/models", nil)
			req.Header.Set("Authorization", "Bearer "+secret)
			resp, callErr := s.client.Do(req)
			if callErr != nil {
				continue
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
			resp.Body.Close()
			if readErr != nil {
				continue
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				_ = s.store.MarkChecked(r.Context(), key.ID, "valid", "reachable", "", "")
				_ = s.store.SaveModelCache(r.Context(), body, key.ID)
				copyResponseHeaders(w.Header(), resp.Header)
				w.Header().Set("X-Keypool-Models-Cache", "miss")
				w.WriteHeader(resp.StatusCode)
				_, _ = w.Write(body)
				return
			}
			c := Classify(resp.StatusCode, resp.Header, body, time.Now().UTC())
			if c.Kind == ErrorAuth {
				_ = s.store.MarkInvalid(r.Context(), key.ID, c.Message)
			}
		}
	}
	if cached, _, cacheErr := s.store.ModelCache(r.Context()); cacheErr == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Warning", `110 - "stale model catalog"`)
		w.Header().Set("X-Keypool-Models-Cache", "stale")
		_, _ = w.Write(cached)
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{"message": "Model catalog is unavailable", "type": "models_unavailable"}})
}

func (s *Service) TestKey(ctx context.Context, key store.Key, inference bool) (map[string]any, error) {
	s.probe.Lock()
	defer s.probe.Unlock()
	secret, err := s.cipher.Decrypt(key.EncryptedKey)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.cfg.UpstreamBaseURL, "/")+"/models", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := s.client.Do(req)
	if err != nil {
		_ = s.store.MarkChecked(ctx, key.ID, "unknown", "degraded", "", err.Error())
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c := Classify(resp.StatusCode, resp.Header, body, time.Now().UTC())
		if c.Kind == ErrorAuth {
			_ = s.store.MarkInvalid(ctx, key.ID, c.Message)
		}
		return map[string]any{"ok": false, "stage": "models", "status": resp.StatusCode, "message": c.Message}, nil
	}
	_ = s.store.MarkChecked(ctx, key.ID, "valid", "reachable", "", "")
	if !inference {
		return map[string]any{"ok": true, "stage": "models", "inference_tested": false}, nil
	}
	settings, _ := s.store.GetSettings(ctx)
	payload, _ := json.Marshal(map[string]any{"model": settings.ProbeModel, "messages": []map[string]string{{"role": "user", "content": "Reply with only OK"}}, "max_tokens": 2, "stream": false})
	fake, _ := http.NewRequest(http.MethodPost, "/", nil)
	probeResp, err := s.callUpstream(ctx, fake, "openai", payload, secret)
	if err != nil {
		return nil, err
	}
	probeBody, _ := io.ReadAll(io.LimitReader(probeResp.Body, 2<<20))
	probeResp.Body.Close()
	c := Classify(probeResp.StatusCode, probeResp.Header, probeBody, time.Now().UTC())
	if c.Kind == ErrorQuota || c.Kind == ErrorAuth {
		_ = s.recordKeyFailure(ctx, key.ID, c, time.Now().UTC())
		return map[string]any{"ok": false, "stage": "inference", "status": probeResp.StatusCode, "kind": c.Kind, "window": c.Window, "reset_at": c.ResetAt, "message": c.Message}, nil
	}
	if probeResp.StatusCode >= 200 && probeResp.StatusCode < 300 {
		_ = s.store.MarkUsed(ctx, key.ID)
		return map[string]any{"ok": true, "stage": "inference", "status": probeResp.StatusCode}, nil
	}
	return map[string]any{"ok": false, "stage": "inference", "status": probeResp.StatusCode, "kind": c.Kind, "message": c.Message}, nil
}

func (s *Service) recordKeyFailure(ctx context.Context, id int64, c Classification, now time.Time) error {
	if c.Kind == ErrorAuth {
		return s.store.MarkInvalid(ctx, id, c.Message)
	}
	if c.Kind == ErrorQuota {
		reset := c.ResetAt
		if reset == nil {
			fallback := now.Add(15 * time.Minute)
			reset = &fallback
		}
		return s.store.MarkQuota(ctx, id, c.Window, reset, c.Message)
	}
	return nil
}

func (s *Service) promoteIfNeeded(ctx context.Context, key store.Key) {
	if key.PoolRole != "active" {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = s.store.SetActive(ctx, key.ID)
	}
}
func (s *Service) finishUnavailable(ctx context.Context, r *store.RequestRecord, started time.Time, class string) {
	r.HTTPStatus = http.StatusServiceUnavailable
	r.Outcome = "error"
	r.ErrorClass = class
	s.finish(ctx, r, store.Usage{State: "unavailable"}, started)
}
func (s *Service) finish(ctx context.Context, r *store.RequestRecord, u store.Usage, started time.Time) {
	finished := time.Now().UTC()
	r.FinishedAt = &finished
	r.LatencyMS = finished.Sub(started).Milliseconds()
	if err := s.store.FinishRequest(ctx, *r, u); err != nil {
		slog.Error("finish request telemetry", "request_id", r.ID, "error", err)
	}
}

func inspectRequest(body []byte) requestMeta {
	var v struct {
		Model    string            `json:"model"`
		Stream   bool              `json:"stream"`
		Messages []json.RawMessage `json:"messages"`
		Tools    []json.RawMessage `json:"tools"`
	}
	_ = json.Unmarshal(body, &v)
	return requestMeta{Model: v.Model, Stream: v.Stream, MessageCount: len(v.Messages), ToolCount: len(v.Tools)}
}
func ensureStreamUsage(body []byte) []byte {
	var v map[string]any
	if json.Unmarshal(body, &v) != nil {
		return body
	}
	if stream, ok := v["stream"].(bool); !ok || !stream {
		return body
	}
	options, _ := v["stream_options"].(map[string]any)
	if options == nil {
		options = map[string]any{}
	}
	if _, exists := options["include_usage"]; !exists {
		options["include_usage"] = true
	}
	v["stream_options"] = options
	encoded, err := json.Marshal(v)
	if err != nil {
		return body
	}
	return encoded
}
func readLimited(r io.Reader, max int64) ([]byte, error) {
	lr := io.LimitReader(r, max+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("request body exceeds %d bytes", max)
	}
	return b, nil
}
func newID() string { b := make([]byte, 16); _, _ = rand.Read(b); return hex.EncodeToString(b) }

func copyRequestHeaders(dst, src http.Header) {
	for k, values := range src {
		if hopHeader(k) || strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "X-Api-Key") || strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Accept-Encoding") {
			continue
		}
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}
func copyResponseHeaders(dst, src http.Header) {
	for k, values := range src {
		if hopHeader(k) || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}
func hopHeader(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	return false
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

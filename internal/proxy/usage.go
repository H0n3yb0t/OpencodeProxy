package proxy

import (
	"encoding/json"

	"github.com/local/opencode-keypool/internal/store"
)

type usageAccumulator struct {
	protocol string
	usage    store.Usage
}

func newUsageAccumulator(protocol string) *usageAccumulator {
	return &usageAccumulator{protocol: protocol, usage: store.Usage{State: "unavailable"}}
}

func (a *usageAccumulator) ObserveJSON(data []byte) {
	var root map[string]any
	if json.Unmarshal(data, &root) != nil {
		return
	}
	if u, ok := root["usage"].(map[string]any); ok {
		a.observeUsage(u)
	}
	if msg, ok := root["message"].(map[string]any); ok {
		if u, ok := msg["usage"].(map[string]any); ok {
			a.observeUsage(u)
		}
	}
}

func (a *usageAccumulator) observeUsage(u map[string]any) {
	raw, _ := json.Marshal(u)
	a.usage.RawJSON = string(raw)
	if a.protocol == "anthropic" {
		uncached, hasInput := intField(u, "input_tokens")
		read, hasRead := intField(u, "cache_read_input_tokens")
		write, hasWrite := intField(u, "cache_creation_input_tokens")
		output, hasOutput := intField(u, "output_tokens")
		if hasInput {
			a.usage.InputUncached = ptr(uncached)
		}
		if hasRead {
			a.usage.CacheRead = ptr(read)
		}
		if hasWrite {
			a.usage.CacheWrite = ptr(write)
		}
		if hasOutput {
			a.usage.OutputTokens = ptr(output)
		}
		if hasInput || hasRead || hasWrite {
			total := value(a.usage.InputUncached) + value(a.usage.CacheRead) + value(a.usage.CacheWrite)
			a.usage.TotalInput = ptr(total)
		}
		if hasInput && hasOutput {
			a.usage.State = "complete"
		} else {
			a.usage.State = "partial"
		}
		return
	}
	input, hasInput := intFieldEither(u, "prompt_tokens", "input_tokens")
	output, hasOutput := intFieldEither(u, "completion_tokens", "output_tokens")
	if hasInput {
		a.usage.TotalInput = ptr(input)
	}
	if hasOutput {
		a.usage.OutputTokens = ptr(output)
	}
	var cached int64
	var hasCached bool
	for _, name := range []string{"prompt_tokens_details", "input_tokens_details"} {
		if details, ok := u[name].(map[string]any); ok {
			if v, ok := intField(details, "cached_tokens"); ok {
				cached, hasCached = v, true
			}
		}
	}
	if hasCached {
		a.usage.CacheRead = ptr(cached)
	}
	if hasInput {
		uncached := input - cached
		if uncached < 0 {
			uncached = 0
		}
		a.usage.InputUncached = ptr(uncached)
	}
	if reasoning, ok := nestedInt(u, "completion_tokens_details", "reasoning_tokens"); ok {
		a.usage.ReasoningTokens = ptr(reasoning)
	}
	if total, ok := intField(u, "total_tokens"); ok {
		a.usage.TotalTokens = ptr(total)
	}
	if hasInput && hasOutput {
		a.usage.State = "complete"
	} else {
		a.usage.State = "partial"
	}
}

func (a *usageAccumulator) Usage() store.Usage { return a.usage }

func intField(m map[string]any, key string) (int64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		v, err := n.Int64()
		return v, err == nil
	default:
		return 0, false
	}
}

func intFieldEither(m map[string]any, first, second string) (int64, bool) {
	if v, ok := intField(m, first); ok {
		return v, true
	}
	return intField(m, second)
}

func nestedInt(m map[string]any, outer, inner string) (int64, bool) {
	v, ok := m[outer].(map[string]any)
	if !ok {
		return 0, false
	}
	return intField(v, inner)
}

func ptr(v int64) *int64 { return &v }
func value(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

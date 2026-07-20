package proxy

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ErrorKind string

const (
	ErrorNone      ErrorKind = ""
	ErrorQuota     ErrorKind = "quota"
	ErrorAuth      ErrorKind = "auth"
	ErrorRateLimit ErrorKind = "rate_limit"
	ErrorUpstream  ErrorKind = "upstream"
	ErrorRequest   ErrorKind = "request"
	ErrorNetwork   ErrorKind = "network"
)

type Classification struct {
	Kind    ErrorKind
	Window  string
	ResetAt *time.Time
	Message string
}

var (
	quotaPattern   = regexp.MustCompile(`(?i)(usage limit reached|limit exhausted|quota exceeded|subscription quota|weekly/monthly limit exhausted|weekly usage limit|monthly usage limit|5\s*hour usage limit)`)
	balancePattern = regexp.MustCompile(`(?i)(insufficient\s+(?:account\s+)?balance|insufficient\s+credits?|not\s+enough\s+credits?|credits?error.*(?:balance|billing)|manage\s+your\s+billing)`)
	authPattern    = regexp.MustCompile(`(?i)(invalid|expired|revoked|unauthorized|authentication|api[ _-]?key|credential)`)
	ratePattern    = regexp.MustCompile(`(?i)(rate[ _-]?limit|too many requests|concurrenc(?:y|ies)|overloaded|temporarily unavailable)`)
	resetInPattern = regexp.MustCompile(`(?i)(?:it\s+will\s+reset\s+in|resets?\s+in|retry\s+in)\s*[:：]?\s*([^\n.;]+)`)
	durationPart   = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)\s*(days?|d|hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)`)
)

func Classify(status int, headers http.Header, body []byte, now time.Time) Classification {
	message := extractMessage(body)
	lower := strings.ToLower(message)
	result := Classification{Message: message}
	if quotaPattern.MatchString(message) || balancePattern.MatchString(message) {
		result.Kind = ErrorQuota
		switch {
		case balancePattern.MatchString(message):
			result.Window = "balance"
		case strings.Contains(lower, "5 hour") || strings.Contains(lower, "5-hour"):
			result.Window = "5h"
		case strings.Contains(lower, "week") && strings.Contains(lower, "month"):
			result.Window = "weekly_or_monthly"
		case strings.Contains(lower, "week"):
			result.Window = "weekly"
		case strings.Contains(lower, "month"):
			result.Window = "monthly"
		default:
			result.Window = "unknown"
		}
		result.ResetAt = parseReset(headers, message, now)
		return result
	}
	if (status == http.StatusUnauthorized || status == http.StatusForbidden) && authPattern.MatchString(message) {
		result.Kind = ErrorAuth
		return result
	}
	if status == http.StatusTooManyRequests || ratePattern.MatchString(message) {
		result.Kind = ErrorRateLimit
		result.ResetAt = parseReset(headers, message, now)
		return result
	}
	if status >= 500 {
		result.Kind = ErrorUpstream
		return result
	}
	if status >= 400 {
		result.Kind = ErrorRequest
	}
	return result
}

func extractMessage(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var value any
	if json.Unmarshal(body, &value) == nil {
		var stringsFound []string
		collectStrings(value, &stringsFound)
		if len(stringsFound) > 0 {
			return strings.Join(stringsFound, " | ")
		}
	}
	return strings.TrimSpace(string(body))
}

func collectStrings(value any, out *[]string) {
	switch v := value.(type) {
	case string:
		*out = append(*out, v)
	case []any:
		for _, item := range v {
			collectStrings(item, out)
		}
	case map[string]any:
		for _, item := range v {
			collectStrings(item, out)
		}
	}
}

func parseReset(headers http.Header, message string, now time.Time) *time.Time {
	if value := headers.Get("Retry-After"); value != "" {
		if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			t := now.Add(time.Duration(seconds) * time.Second)
			return &t
		}
		if t, err := http.ParseTime(value); err == nil {
			return &t
		}
	}
	match := resetInPattern.FindStringSubmatch(message)
	if len(match) < 2 {
		return nil
	}
	d := parseHumanDuration(match[1])
	if d <= 0 {
		return nil
	}
	t := now.Add(d)
	return &t
}

func parseHumanDuration(value string) time.Duration {
	var total time.Duration
	for _, match := range durationPart.FindAllStringSubmatch(value, -1) {
		n, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			continue
		}
		unit := strings.ToLower(match[2])
		switch unit[0] {
		case 'd':
			total += time.Duration(n * float64(24*time.Hour))
		case 'h':
			total += time.Duration(n * float64(time.Hour))
		case 'm':
			total += time.Duration(n * float64(time.Minute))
		case 's':
			total += time.Duration(n * float64(time.Second))
		}
	}
	return total
}

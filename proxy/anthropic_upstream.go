package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const defaultAnthropicAPIBaseURL = "https://api.anthropic.com"

// Bound buffered non-stream responses so a malformed upstream cannot exhaust memory.
// This remains large enough for long Claude/tool responses while keeping the
// direct path consistent with the existing bounded upstream error readers.
const anthropicMaxNonStreamResponseBody = 128 << 20

func ExecuteAnthropicMessagesRequest(ctx context.Context, account *auth.Account, requestBody []byte, proxyOverride string, headers http.Header) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if account == nil || !account.IsAnthropicAPI() {
		return nil, fmt.Errorf("account is not an Anthropic API account")
	}
	account.Mu().RLock()
	baseURL := strings.TrimRight(strings.TrimSpace(account.BaseURL), "/")
	apiKey := strings.TrimSpace(account.APIKey)
	proxyURL := strings.TrimSpace(account.ProxyURL)
	customHeaders := make(map[string]string, len(account.CustomHeaders))
	for k, v := range account.CustomHeaders {
		customHeaders[k] = v
	}
	account.Mu().RUnlock()
	if baseURL == "" {
		baseURL = defaultAnthropicAPIBaseURL
	}
	if apiKey == "" {
		return nil, fmt.Errorf("Anthropic API account has no API key")
	}
	switch lowerBaseURL := strings.ToLower(baseURL); {
	case strings.HasSuffix(lowerBaseURL, "/v1/messages"):
		// The account may use either an API base URL or the concrete endpoint.
	case strings.HasSuffix(lowerBaseURL, "/v1"):
		baseURL += "/messages"
	default:
		baseURL += "/v1/messages"
	}
	if proxyOverride != "" {
		proxyURL = proxyOverride
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	for k, values := range headers {
		if isAnthropicForbiddenForwardHeader(k) {
			continue
		}
		for _, value := range values {
			req.Header.Add(k, value)
		}
	}
	for k, v := range customHeaders {
		if isAnthropicForbiddenForwardHeader(k) {
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Del("Authorization")
	req.Header.Del("anthropic-auth-token")
	resp, err := getPooledClient(account, proxyURL).Do(req)
	if err != nil {
		if shouldRecyclePooledClient(err) {
			recyclePooledClient(account, proxyURL)
		}
		return nil, err
	}
	return resp, nil
}

func isAnthropicCredentialHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "x-api-key", "anthropic-auth-token", "anthropic-version":
		return true
	default:
		return false
	}
}

// isAnthropicForbiddenForwardHeader identifies headers that must never be
// copied from a downstream request or account-level custom header into the
// Anthropic request. Besides credentials, hop-by-hop headers are controlled
// by the transport connection and forwarding them can cause connection reuse
// or proxy semantics to leak across the boundary.
func isAnthropicForbiddenForwardHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if isAnthropicCredentialHeader(name) {
		return true
	}
	switch name {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
		"content-length", "host":
		return true
	default:
		return false
	}
}

func copyAnthropicResponseHeaders(dst http.ResponseWriter, src http.Header) {
	for key, values := range src {
		normalized := strings.ToLower(strings.TrimSpace(key))
		allowed := normalized == "cache-control" || normalized == "content-language" || normalized == "content-type" ||
			normalized == "retry-after" || normalized == "request-id" || normalized == "x-request-id" ||
			strings.HasPrefix(normalized, "anthropic-ratelimit-") || strings.HasPrefix(normalized, "x-ratelimit-")
		if !allowed {
			continue
		}
		for _, value := range values {
			if !strings.ContainsAny(value, "\r\n") {
				dst.Header().Add(key, value)
			}
		}
	}
}

type anthropicDirectForwardResult struct {
	firstTokenMs int
	wroteBody    bool
	durationMs   int
	readErr      error
	writeErr     error
	usage        *UsageInfo
	outcome      streamOutcome
}

func forwardAnthropicDirectResponse(c *gin.Context, resp *http.Response, stream bool, started time.Time, onFirstToken func()) anthropicDirectForwardResult {
	result := anthropicDirectForwardResult{}
	if resp == nil || resp.Body == nil {
		result.readErr = fmt.Errorf("Anthropic upstream returned an empty response body")
		result.outcome = classifyStreamOutcome(nil, result.readErr, nil, false)
		return result
	}
	if stream {
		flusher, _ := c.Writer.(http.Flusher)
		var pending bytes.Buffer
		visible := false
		terminal := false
		headersCopied := false
		copyHeaders := func() {
			if headersCopied {
				return
			}
			copyAnthropicResponseHeaders(c.Writer, resp.Header)
			c.Header("Content-Type", "text/event-stream; charset=utf-8")
			c.Header("Cache-Control", "no-cache")
			c.Header("Connection", "keep-alive")
			c.Header("X-Accel-Buffering", "no")
			headersCopied = true
		}
		writeRaw := func(raw []byte) bool {
			if len(raw) == 0 {
				return true
			}
			copyHeaders()
			n, err := c.Writer.Write(raw)
			if n > 0 {
				result.wroteBody = true
			}
			if err == nil && n != len(raw) {
				err = io.ErrShortWrite
			}
			if err != nil {
				result.writeErr = err
				return false
			}
			return true
		}

		parseErr := readRawGrokSSEFrames(resp.Body, func(frame rawGrokSSEFrame) bool {
			if frame.HasData && !frame.Done {
				result.usage = mergeGrokNativeUsage(result.usage, grokNativeUsage(GrokProtocolMessages, frame.Data))
			}
			isTerminal, failed := false, false
			if frame.HasData && !frame.Done {
				isTerminal, failed = grokNativeTerminalEvent(GrokProtocolMessages, frame.Data)
			}
			if isTerminal {
				terminal = true
				if failed {
					result.outcome = anthropicDirectFailureOutcome(frame.Data)
				}
			}
			isVisible := frame.HasData && !frame.Done && grokNativeVisibleEvent(GrokProtocolMessages, frame.Data)
			if !visible && !isVisible && !isTerminal {
				if pending.Len()+len(frame.Raw) > grokMaxNativeSSEPendingBytes {
					result.readErr = fmt.Errorf("Anthropic pre-output SSE exceeds %d bytes", grokMaxNativeSSEPendingBytes)
					return false
				}
				pending.Write(frame.Raw)
				return true
			}
			// Keep retryable pre-output errors silent so the handler can rotate
			// accounts without corrupting the downstream SSE stream.
			if failed && !visible && !result.wroteBody {
				pending.Reset()
				return false
			}
			if isVisible && !visible {
				visible = true
				result.firstTokenMs = max(int(time.Since(started).Milliseconds()), 1)
				if onFirstToken != nil {
					onFirstToken()
				}
			} else if isTerminal {
				// Empty but valid responses still terminate the first-token watchdog.
				if result.firstTokenMs == 0 {
					result.firstTokenMs = max(int(time.Since(started).Milliseconds()), 1)
				}
				if onFirstToken != nil {
					onFirstToken()
				}
			}
			if pending.Len() > 0 {
				if !writeRaw(pending.Bytes()) {
					return false
				}
				pending.Reset()
			}
			if !writeRaw(frame.Raw) {
				return false
			}
			if flusher != nil {
				flusher.Flush()
			}
			return !isTerminal
		})
		if parseErr != nil {
			result.readErr = parseErr
		}
		if result.outcome.logStatusCode == 0 {
			complete := terminal && result.readErr == nil && result.writeErr == nil
			result.outcome = classifyStreamOutcome(c.Request.Context().Err(), result.readErr, result.writeErr, complete)
		}
	} else {
		// Read and validate the complete non-stream response before committing any
		// bytes, preserving safe retry after a truncated upstream body.
		body, err := readAllLimited(resp.Body, anthropicMaxNonStreamResponseBody)
		if err != nil {
			result.readErr = err
		} else if !json.Valid(body) {
			result.readErr = fmt.Errorf("Anthropic upstream returned invalid JSON")
		} else if failed := anthropicDirectFailureOutcome(body); failed.logStatusCode != 0 {
			result.outcome = failed
		} else {
			result.usage = grokNativeUsage(GrokProtocolMessages, body)
			copyAnthropicResponseHeaders(c.Writer, resp.Header)
			c.Header("Content-Type", "application/json")
			n, writeErr := c.Writer.Write(body)
			if n > 0 {
				result.wroteBody = true
				result.firstTokenMs = max(int(time.Since(started).Milliseconds()), 1)
				if onFirstToken != nil {
					onFirstToken()
				}
			}
			if writeErr == nil && n != len(body) {
				writeErr = io.ErrShortWrite
			}
			result.writeErr = writeErr
		}
		if result.outcome.logStatusCode == 0 {
			complete := result.readErr == nil && result.writeErr == nil && result.wroteBody
			result.outcome = classifyStreamOutcome(c.Request.Context().Err(), result.readErr, result.writeErr, complete)
		}
	}
	result.durationMs = int(time.Since(started).Milliseconds())
	return result
}

func anthropicDirectFailureOutcome(payload []byte) streamOutcome {
	root := gjson.ParseBytes(payload)
	if !root.Exists() || (root.Get("type").String() != "error" && !root.Get("error").Exists()) {
		return streamOutcome{}
	}
	errType := strings.ToLower(strings.TrimSpace(root.Get("error.type").String()))
	status := responseFailedStatusCode(payload)
	switch errType {
	case "invalid_request_error":
		status = http.StatusBadRequest
	case "authentication_error":
		status = http.StatusUnauthorized
	case "permission_error":
		status = http.StatusForbidden
	case "not_found_error":
		status = http.StatusNotFound
	case "rate_limit_error":
		status = http.StatusTooManyRequests
	case "overloaded_error":
		status = 529
	}
	kind := classifyHTTPFailure(status)
	if kind == "" && status == http.StatusTooManyRequests {
		kind = "rate_limit"
	}
	return streamOutcome{
		logStatusCode:  status,
		failureKind:    kind,
		failureMessage: anthropicErrorMessage(payload),
		penalize:       status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusTooManyRequests || status >= 500,
	}
}

func anthropicErrorMessage(body []byte) string {
	var envelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) == nil && strings.TrimSpace(envelope.Error.Message) != "" {
		return strings.TrimSpace(envelope.Error.Message)
	}
	if message := strings.TrimSpace(string(body)); message != "" {
		return message
	}
	return "Anthropic upstream request failed"
}

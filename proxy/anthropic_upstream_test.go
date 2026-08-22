package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/gin-gonic/gin"
)

func TestExecuteAnthropicMessagesRequestPreservesRequestAndRewritesCredentials(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"hello"}],"stream":false}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %q, want /v1/messages", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "sk-anthropic" {
			t.Errorf("x-api-key = %q, want account key", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Errorf("anthropic-version = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization leaked upstream: %q", got)
		}
		if got := r.Header.Get("anthropic-auth-token"); got != "" {
			t.Errorf("anthropic-auth-token leaked upstream: %q", got)
		}
		if got := r.Header.Get("Connection"); got != "" {
			t.Errorf("Connection leaked upstream: %q", got)
		}
		gotBody, _ := io.ReadAll(r.Body)
		if string(gotBody) != string(body) {
			t.Errorf("body changed: got %s, want %s", gotBody, body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_test"}`))
	}))
	t.Cleanup(server.Close)

	account := &auth.Account{
		DBID:         101,
		UpstreamType: auth.UpstreamAnthropic,
		BaseURL:      server.URL,
		APIKey:       "sk-anthropic",
		CustomHeaders: map[string]string{
			"X-Test-Account":    "yes",
			"Authorization":     "should-not-leak",
			"X-Api-Key":         "custom-key-must-not-win",
			"Anthropic-Version": "custom-version-must-not-win",
			"Connection":        "close",
		},
	}
	resp, err := ExecuteAnthropicMessagesRequest(context.Background(), account, body, "", http.Header{
		"Authorization":        []string{"Bearer downstream"},
		"x-api-key":            []string{"downstream-key"},
		"anthropic-auth-token": []string{"downstream-token"},
		"Connection":           []string{"close"},
		"X-Test-Downstream":    []string{"yes"},
	})
	if err != nil {
		t.Fatalf("ExecuteAnthropicMessagesRequest() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("response content-type = %q", got)
	}
}

func TestExecuteAnthropicMessagesRequestRejectsMissingAPIKey(t *testing.T) {
	account := &auth.Account{
		DBID:         104,
		UpstreamType: auth.UpstreamAnthropic,
		BaseURL:      "https://api.anthropic.com",
	}
	if _, err := ExecuteAnthropicMessagesRequest(context.Background(), account, []byte(`{"model":"claude-3","messages":[]}`), "", nil); err == nil {
		t.Fatal("expected missing API key to be rejected")
	}
}

func TestExecuteAnthropicMessagesRequestAppendsMessagesToV1BaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %q, want /v1/messages", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	account := &auth.Account{
		DBID:         102,
		UpstreamType: auth.UpstreamAnthropic,
		BaseURL:      server.URL + "/v1/",
		APIKey:       "sk-anthropic",
	}
	resp, err := ExecuteAnthropicMessagesRequest(context.Background(), account, []byte(`{"model":"claude-3","messages":[]}`), "", nil)
	if err != nil {
		t.Fatalf("ExecuteAnthropicMessagesRequest() error = %v", err)
	}
	resp.Body.Close()
}

func TestExecuteAnthropicMessagesRequestAcceptsConcreteMessagesEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %q, want /v1/messages", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	account := &auth.Account{
		DBID:         103,
		UpstreamType: auth.UpstreamAnthropic,
		BaseURL:      server.URL + "/v1/messages",
		APIKey:       "sk-anthropic",
	}
	resp, err := ExecuteAnthropicMessagesRequest(context.Background(), account, []byte(`{"model":"claude-3","messages":[]}`), "", nil)
	if err != nil {
		t.Fatalf("ExecuteAnthropicMessagesRequest() error = %v", err)
	}
	resp.Body.Close()
}

type anthropicReadThenFail struct {
	data []byte
	done bool
}

func (r *anthropicReadThenFail) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, r.data), nil
	}
	return 0, io.ErrUnexpectedEOF
}

func TestForwardAnthropicDirectNonStreamDoesNotCommitTruncatedJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(&anthropicReadThenFail{data: []byte(`{"type":"message"`)}),
	}

	result := forwardAnthropicDirectResponse(ctx, resp, false, time.Now(), nil)
	if result.wroteBody || writer.Body.Len() != 0 {
		t.Fatalf("truncated JSON was committed: wrote=%v body=%q", result.wroteBody, writer.Body.String())
	}
	if result.readErr == nil || result.outcome.logStatusCode != logStatusUpstreamStreamBreak {
		t.Fatalf("result = %+v, want upstream stream break", result)
	}
}

func TestForwardAnthropicDirectStreamBuffersPreOutputFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	raw := "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":9}}}\n\n" +
		"event: error\n" +
		"data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy\"}}\n\n"
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(raw))}

	result := forwardAnthropicDirectResponse(ctx, resp, true, time.Now(), nil)
	if result.wroteBody || writer.Body.Len() != 0 {
		t.Fatalf("pre-output error leaked downstream: wrote=%v body=%q", result.wroteBody, writer.Body.String())
	}
	if result.outcome.logStatusCode != 529 || !result.outcome.penalize {
		t.Fatalf("outcome = %+v, want retryable 529", result.outcome)
	}
}

func TestForwardAnthropicDirectStreamPreservesFramesAndUsage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	raw := "event: message_start\r\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7}}}\r\n\r\n" +
		"event: content_block_delta\r\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\r\n\r\n" +
		"event: message_delta\r\n" +
		"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\r\n\r\n" +
		"event: message_stop\r\n" +
		"data: {\"type\":\"message_stop\"}\r\n\r\n"
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
			"Request-Id":   []string{"req_test"},
			"Set-Cookie":   []string{"secret=must-not-leak"},
		},
		Body: io.NopCloser(strings.NewReader(raw)),
	}
	firstTokenCalled := false

	result := forwardAnthropicDirectResponse(ctx, resp, true, time.Now(), func() { firstTokenCalled = true })
	if result.outcome.logStatusCode != http.StatusOK {
		t.Fatalf("outcome = %+v, want 200", result.outcome)
	}
	if writer.Body.String() != raw {
		t.Fatalf("SSE changed:\ngot  %q\nwant %q", writer.Body.String(), raw)
	}
	if !firstTokenCalled || result.firstTokenMs <= 0 {
		t.Fatalf("first token not recorded: called=%v ms=%d", firstTokenCalled, result.firstTokenMs)
	}
	if result.usage == nil || result.usage.InputTokens != 7 || result.usage.OutputTokens != 3 || result.usage.TotalTokens != 10 {
		t.Fatalf("usage = %+v, want input=7 output=3 total=10", result.usage)
	}
	if got := writer.Header().Get("Request-Id"); got != "req_test" {
		t.Fatalf("Request-Id = %q", got)
	}
	if got := writer.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("Set-Cookie leaked downstream: %q", got)
	}
}

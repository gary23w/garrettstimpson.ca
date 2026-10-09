package llm

import (
	"context"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type StreamEventType string

const (
	SEMessageStart      StreamEventType = "message_start"
	SETextDelta         StreamEventType = "text_delta"
	SEThinkingDelta     StreamEventType = "thinking_delta"
	SEThinkingSignature StreamEventType = "thinking_signature"
	SEToolUseStart      StreamEventType = "tool_use_start"
	SEToolInputJSON     StreamEventType = "tool_input_delta"
	SEMessageDelta      StreamEventType = "message_delta"
	SEMessageStop       StreamEventType = "message_stop"
)

type StreamEvent struct {
	Type       StreamEventType
	Text       string
	ToolID     string
	ToolName   string
	StopReason string
	Usage      Usage
}

type Format string

const (
	FormatAnthropic Format = "anthropic"
	FormatOpenAI    Format = "openai"

	FormatOpenAIResponses Format = "openai-responses"
)

const MaxTokensFieldCompletion = "max_completion_tokens"

type Config struct {
	Format     Format
	BaseURL    string
	APIKey     string
	Model      string
	APIVersion string
	HTTPClient *http.Client

	Proxy string

	MaxRetries int

	RetryInterval time.Duration

	EmptyResponseRetries int

	EmptyResponseInterval time.Duration

	RateLimit *RateLimit

	ThinkingType string

	ReasoningEffort string

	MaxTokensField string

	limiter *rateLimiter
}

func (c Config) retries() int {
	if c.MaxRetries == 0 {
		return 3
	}
	if c.MaxRetries < 0 {
		return 0
	}
	return c.MaxRetries
}

func (c Config) retryDelay(attempt int) time.Duration {
	if c.RetryInterval > 0 {
		return c.RetryInterval
	}
	return expBackoff(attempt)
}

func (c Config) emptyRetries() int {
	if c.EmptyResponseRetries == 0 {
		return emptyResponseRetries
	}
	if c.EmptyResponseRetries < 0 {
		return 0
	}
	return c.EmptyResponseRetries
}

func (c Config) emptyRetryDelay(attempt int) time.Duration {
	if c.EmptyResponseInterval > 0 {
		return c.EmptyResponseInterval
	}
	return expBackoff(attempt)
}

type Provider interface {
	Stream(ctx context.Context, req CompletionRequest) iter.Seq2[StreamEvent, error]
	Complete(ctx context.Context, req CompletionRequest) (Message, string, Usage, error)
}

func NewProvider(cfg Config) (Provider, error) {
	if cfg.HTTPClient == nil {
		client, err := defaultHTTPClient(cfg.Proxy)
		if err != nil {
			return nil, err
		}
		cfg.HTTPClient = client
	}
	if cfg.RateLimit != nil {
		cfg.limiter = newRateLimiter(*cfg.RateLimit)
	}
	switch cfg.Format {
	case FormatAnthropic:
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("ANTHROPIC_API_KEY")
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = envOr("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
		}
		if cfg.APIVersion == "" {
			cfg.APIVersion = "2023-06-01"
		}
		return &anthropicProvider{cfg: cfg}, nil
	case FormatOpenAI:
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("OPENAI_API_KEY")
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = envOr("OPENAI_BASE_URL", "https://api.openai.com/v1")
		}
		return &openaiProvider{cfg: cfg}, nil
	case FormatOpenAIResponses:
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("OPENAI_API_KEY")
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = envOr("OPENAI_BASE_URL", "https://api.openai.com/v1")
		}
		return &openaiResponsesProvider{cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("llm: unknown format %q (use anthropic, openai or openai-responses)", cfg.Format)
	}
}

func defaultHTTPClient(proxy string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxy == "" {
		tr.Proxy = http.ProxyFromEnvironment
		return &http.Client{Transport: tr}, nil
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("llm: invalid proxy %q: %w", proxy, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	case "":
		return nil, fmt.Errorf("llm: proxy %q missing scheme (use http://, https:// or socks5://)", proxy)
	default:
		return nil, fmt.Errorf("llm: unsupported proxy scheme %q (use http, https or socks5)", u.Scheme)
	}
	tr.Proxy = http.ProxyURL(u)
	return &http.Client{Transport: tr}, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func joinSystem(segs []string) string {
	parts := make([]string, 0, len(segs))
	for _, s := range segs {
		if s = strings.TrimSpace(s); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n\n")
}

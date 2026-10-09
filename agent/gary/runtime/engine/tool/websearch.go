package tool

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
	"golang.org/x/net/html"
)

type SearchResult struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Position    int    `json:"position"`
}

type searchProvider interface {
	Name() string
	Search(ctx context.Context, query string, limit int) ([]SearchResult, error)
}

type WebSearchConfig struct {
	Backend string

	BraveAPIKey string

	TavilyAPIKey string

	DeepSeekBaseURL string
	DeepSeekAPIKey  string
	DeepSeekModel   string

	Proxy string

	CACert      string
	InsecureTLS bool
}

func NewWebSearch(cfg WebSearchConfig) (CoreTool, error) {
	prov, err := newSearchProvider(cfg)
	if err != nil {
		return nil, err
	}
	return Build(Spec{
		Name:        "web_search",
		Description: "Search the web and return a ranked list of results (title, URL, description) — metadata only, up to 5 by default. Use WebFetch to read the full content of a specific URL. This makes an external network request.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string", "description": "The search query."},
				"limit": map[string]any{"type": "integer", "description": "Maximum number of results to return (1-20). Default 5.", "minimum": 1, "maximum": 20},
			},
			"required": []any{"query"},
		},

		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(_ context.Context, input json.RawMessage, _ permission.Context) permission.Decision {
			var in struct {
				Query string `json:"query"`
			}
			_ = json.Unmarshal(input, &in)
			return permission.AskUser("web search: " + in.Query)
		},
		Run: webSearchRunner(prov),
	}), nil
}

func newSearchProvider(cfg WebSearchConfig) (searchProvider, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	if backend == "" {
		backend = "ddgs"
	}
	client := newFetchClient(WebFetchConfig{Proxy: cfg.Proxy, CACert: cfg.CACert, InsecureTLS: cfg.InsecureTLS})
	switch backend {
	case "ddgs":
		return &ddgsProvider{client: client, endpoint: ddgsEndpoint}, nil
	case "brave-free":
		key := strings.TrimSpace(cfg.BraveAPIKey)
		if key == "" {
			return nil, fmt.Errorf("web_search: backend %q requires a Brave Search API key", backend)
		}
		return &braveProvider{apiKey: key, client: client, endpoint: braveEndpoint}, nil
	case "tavily":
		key := strings.TrimSpace(cfg.TavilyAPIKey)
		if key == "" {
			return nil, fmt.Errorf("web_search: backend %q requires a Tavily API key", backend)
		}
		return &tavilyProvider{apiKey: key, client: client, endpoint: tavilyEndpoint}, nil
	case "deepseek":
		key := strings.TrimSpace(cfg.DeepSeekAPIKey)
		if key == "" {
			return nil, fmt.Errorf("web_search: backend %q requires a DeepSeek API key", backend)
		}
		base := strings.TrimSpace(cfg.DeepSeekBaseURL)
		if base == "" {
			return nil, fmt.Errorf("web_search: backend %q requires the Anthropic-format base URL of the DeepSeek profile", backend)
		}
		model := strings.TrimSpace(cfg.DeepSeekModel)
		if model == "" {
			return nil, fmt.Errorf("web_search: backend %q requires a model name", backend)
		}
		return &deepseekProvider{apiKey: key, model: model, client: client, endpoint: deepseekMessagesURL(base)}, nil
	default:
		return nil, fmt.Errorf("web_search: unknown backend %q (want \"ddgs\", \"brave-free\", \"tavily\", or \"deepseek\")", backend)
	}
}

func WebSearchProbe(ctx context.Context, cfg WebSearchConfig, query string, limit int) ([]SearchResult, error) {
	prov, err := newSearchProvider(cfg)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 3
	}
	return prov.Search(ctx, query, limit)
}

func webSearchRunner(prov searchProvider) func(context.Context, json.RawMessage, *ToolContext) (Result, error) {
	return func(ctx context.Context, input json.RawMessage, _ *ToolContext) (Result, error) {
		var in struct {
			Query string `json:"query"`
			Limit int    `json:"limit"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return Result{}, err
		}
		query := strings.TrimSpace(in.Query)
		if query == "" {
			return Errorf("Error: query must not be empty"), nil
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 5
		}
		if limit > 20 {
			limit = 20
		}

		wall := 30 * time.Second
		if tp, ok := prov.(interface{ Timeout() time.Duration }); ok {
			wall = tp.Timeout()
		}
		cctx, cancel := context.WithTimeout(ctx, wall)
		defer cancel()
		results, err := prov.Search(cctx, query, limit)
		if err != nil {
			return Errorf(fmt.Sprintf("Error searching web via %s: %s", prov.Name(), err.Error())), nil
		}
		out, _ := json.MarshalIndent(map[string]any{
			"backend": prov.Name(),
			"query":   query,
			"results": results,
		}, "", "  ")
		return Text(truncate(string(out), 50000)), nil
	}
}

const ddgsEndpoint = "https://html.duckduckgo.com/html/"

type ddgsProvider struct {
	client   *http.Client
	endpoint string
}

func (p *ddgsProvider) Name() string { return "ddgs" }

func (p *ddgsProvider) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	form := url.Values{"q": {query}, "kl": {"wt-wt"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Referer", "https://html.duckduckgo.com/")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("DuckDuckGo is rate-limiting (HTTP %d); try again later or switch backend", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DuckDuckGo returned HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("could not parse DuckDuckGo response: %w", err)
	}
	return parseDDGS(doc, limit), nil
}

func parseDDGS(doc *html.Node, limit int) []SearchResult {
	type hit struct{ title, href string }
	var hits []hit
	var snippets []string

	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" && hasClass(n, "result__a") {
			hits = append(hits, hit{title: nodeText(n), href: unwrapDDGHref(attr(n, "href"))})
		}
		if n.Type == html.ElementNode && hasClass(n, "result__snippet") {
			snippets = append(snippets, nodeText(n))
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	var out []SearchResult
	for i, h := range hits {
		if len(out) >= limit {
			break
		}
		if h.href == "" {
			continue
		}
		desc := ""
		if i < len(snippets) {
			desc = snippets[i]
		}
		out = append(out, SearchResult{
			Title:       strings.TrimSpace(h.title),
			URL:         h.href,
			Description: strings.TrimSpace(desc),
			Position:    len(out) + 1,
		})
	}
	return out
}

func unwrapDDGHref(href string) string {
	if href == "" {
		return ""
	}
	if strings.HasPrefix(href, "//") {
		href = "https:" + href
	}
	u, err := url.Parse(href)
	if err != nil {
		return href
	}
	if target := u.Query().Get("uddg"); target != "" {
		return target
	}
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	return ""
}

const braveEndpoint = "https://api.search.brave.com/res/v1/web/search"

type braveProvider struct {
	apiKey   string
	client   *http.Client
	endpoint string
}

func (p *braveProvider) Name() string { return "brave-free" }

func (p *braveProvider) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	count := min(limit, 20)
	q := url.Values{"q": {query}, "count": {fmt.Sprintf("%d", count)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Subscription-Token", p.apiKey)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Brave Search returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Web struct {
			Results []struct {
				Title       string `json:"title"`
				URL         string `json:"url"`
				Description string `json:"description"`
			} `json:"results"`
		} `json:"web"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("could not parse Brave Search response: %w", err)
	}
	var out []SearchResult
	for _, r := range payload.Web.Results {
		if len(out) >= limit {
			break
		}
		out = append(out, SearchResult{
			Title:       r.Title,
			URL:         r.URL,
			Description: r.Description,
			Position:    len(out) + 1,
		})
	}
	return out, nil
}

const tavilyEndpoint = "https://api.tavily.com/search"

type tavilyProvider struct {
	apiKey   string
	client   *http.Client
	endpoint string
}

func (p *tavilyProvider) Name() string { return "tavily" }

func (p *tavilyProvider) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	body, err := json.Marshal(map[string]any{
		"api_key":      p.apiKey,
		"query":        query,
		"max_results":  min(limit, 20),
		"search_depth": "basic",
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Tavily Search returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Results []struct {
			Title   string `json:"title"`
			URL     string `json:"url"`
			Content string `json:"content"`
		} `json:"results"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("could not parse Tavily Search response: %w", err)
	}
	var out []SearchResult
	for _, r := range payload.Results {
		if len(out) >= limit {
			break
		}
		out = append(out, SearchResult{
			Title:       r.Title,
			URL:         r.URL,
			Description: r.Content,
			Position:    len(out) + 1,
		})
	}
	return out, nil
}

func deepseekMessagesURL(base string) string {
	b := strings.TrimRight(strings.TrimSpace(base), "/")
	switch {
	case strings.HasSuffix(b, "/v1/messages"):
		return b
	case strings.HasSuffix(b, "/v1"):
		return b + "/messages"
	default:
		return b + "/v1/messages"
	}
}

type deepseekProvider struct {
	apiKey   string
	model    string
	client   *http.Client
	endpoint string
}

func (p *deepseekProvider) Name() string { return "deepseek" }

func (p *deepseekProvider) Timeout() time.Duration { return 120 * time.Second }

func (p *deepseekProvider) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {

	maxUses := (limit + 9) / 10
	if maxUses < 1 {
		maxUses = 1
	}
	if maxUses > 3 {
		maxUses = 3
	}
	body, err := json.Marshal(map[string]any{
		"model":      p.model,
		"max_tokens": 1024,
		"stream":     true,
		"messages": []any{map[string]any{
			"role":    "user",
			"content": "Search the web for: " + query + "\n\nUse the web_search tool. Do not answer from memory; reply with at most one short sentence once the search is done.",
		}},
		"tools": []any{map[string]any{
			"type":     "web_search_20250305",
			"name":     "web_search",
			"max_uses": maxUses,
		}},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("DeepSeek search returned HTTP %d: %s", resp.StatusCode, truncate(strings.TrimSpace(string(raw)), 300))
	}
	return parseDeepSeekStream(resp.Body, limit)
}

func parseDeepSeekStream(r io.Reader, limit int) ([]SearchResult, error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxFetchBytes))

	sc.Buffer(make([]byte, 0, 64*1024), maxFetchBytes)

	var out []SearchResult
	var toolErr string
	seen := map[string]bool{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(line[len("data:"):])
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var frame struct {
			Type         string `json:"type"`
			ContentBlock struct {
				Type    string `json:"type"`
				Content []struct {
					Type      string `json:"type"`
					Title     string `json:"title"`
					URL       string `json:"url"`
					ErrorCode string `json:"error_code"`
				} `json:"content"`
			} `json:"content_block"`
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			continue
		}
		if frame.Type == "error" && frame.Error.Message != "" {
			return nil, fmt.Errorf("DeepSeek search stream error: %s", frame.Error.Message)
		}
		if frame.Type != "content_block_start" || frame.ContentBlock.Type != "web_search_tool_result" {
			continue
		}
		for _, hit := range frame.ContentBlock.Content {

			if hit.ErrorCode != "" {
				if toolErr == "" {
					toolErr = hit.ErrorCode
				}
				continue
			}
			if hit.URL == "" || seen[hit.URL] {
				continue
			}
			seen[hit.URL] = true
			out = append(out, SearchResult{
				Title: firstNonEmpty(hit.Title, hostOf(hit.URL)),
				URL:   hit.URL,

				Position: len(out) + 1,
			})
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("could not read DeepSeek search stream: %w", err)
	}

	if len(out) == 0 && toolErr != "" {
		return nil, fmt.Errorf("DeepSeek web search failed: %s", toolErr)
	}
	return out, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

func hasClass(n *html.Node, class string) bool {
	for _, c := range strings.Fields(attr(n, "class")) {
		if c == class {
			return true
		}
	}
	return false
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	textOnly(&b, n)
	return strings.Join(strings.Fields(b.String()), " ")
}

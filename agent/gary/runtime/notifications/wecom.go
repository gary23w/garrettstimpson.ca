package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

const weComMarkdownLimit = 4096

type weComChannel struct{}

func (weComChannel) Kind() string { return KindWeCom }

func (weComChannel) DefaultRatePerMin() int { return 20 }

func (weComChannel) SecretKeys() []string { return []string{"webhook"} }

func (weComChannel) DestinationKeys() []string { return []string{"webhook"} }

func (weComChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Missing webhook address")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Invalid webhook address: %w", err)
	}
	return nil
}

func (c weComChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}

	content, kept := markdownBody(m, weComMarkdownLimit)
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]any{"content": content},
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("Failed to parse Enterprise WeChat response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {

		if res.ErrCode == 45009 {
			return 0, fmt.Errorf("Enterprise WeChat traffic limit %d: %s", res.ErrCode, res.ErrMsg)
		}

		return 0, Permanent(fmt.Errorf("Enterprise WeChat returns error %d: %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}

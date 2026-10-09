package db

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type ChatMention struct {
	Kind        string `json:"kind"`
	ID          int64  `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

type ChatMentionPage struct {
	Items      []ChatMention `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

var ErrInvalidChatMentionCursor = errors.New("The pagination position is invalid, please search again")

type chatMentionCursor struct {
	ID    int64  `json:"id"`
	Kind  string `json:"kind"`
	Exact bool   `json:"exact"`
	Scope string `json:"scope"`
	Query string `json:"query"`
}

func ValidChatMentionKind(kind string) bool {
	switch kind {
	case "finding", "company", "asset", "endpoint", "ip", "app", "root_domain", "subdomain", "service":
		return true
	}
	return false
}

func (d *DB) SearchChatMentions(ctx context.Context, kind, query string) ([]ChatMention, error) {
	page, err := d.SearchChatMentionsPage(ctx, kind, query, "")
	return page.Items, err
}

func (d *DB) SearchChatMentionsPage(ctx context.Context, kind, query, cursor string) (ChatMentionPage, error) {
	page := ChatMentionPage{Items: make([]ChatMention, 0)}
	if kind != "" && !ValidChatMentionKind(kind) {
		return page, fmt.Errorf("Unsupported reference type")
	}
	var after chatMentionCursor
	if cursor != "" {
		if len(cursor) > 2048 {
			return page, ErrInvalidChatMentionCursor
		}
		blob, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || json.Unmarshal(blob, &after) != nil || after.ID <= 0 ||
			!ValidChatMentionKind(after.Kind) || after.Scope != kind || after.Query != query {
			return page, ErrInvalidChatMentionCursor
		}
	}
	pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(query) + "%"
	rows, err := d.QueryContext(ctx, "SELECT kind, id, left(label, 160), left(description, 240) FROM (\n (SELECT 'finding' AS kind, id, COALESCE(NULLIF(name,''), vulnclass) AS label,\n         concat_ws(' · ', severity, status, left(summary, 160)) AS description\n  FROM findings WHERE ($1='' OR $1='finding') AND\n    ($2='' OR id::text=$2 OR concat_ws(' ',name,vulnclass,summary) ILIKE $3)\n    AND ($4::bigint=0 OR (id::text=$2)<$6 OR ((id::text=$2)=$6 AND (id<$4 OR (id=$4 AND 'finding'>$5))))\n  ORDER BY (id::text=$2) DESC, id DESC LIMIT 21)\n UNION ALL\n (SELECT 'company', id, name, nkey FROM companies\n  WHERE ($1='' OR $1='company') AND ($2='' OR id::text=$2 OR name ILIKE $3 OR nkey ILIKE $3)\n    AND ($4::bigint=0 OR (id::text=$2)<$6 OR ((id::text=$2)=$6 AND (id<$4 OR (id=$4 AND 'company'>$5))))\n  ORDER BY (id::text=$2) DESC, id DESC LIMIT 21)\n UNION ALL\n (SELECT type, id,\n    CASE WHEN type='endpoint' THEN concat_ws(' ',NULLIF(method,''),url)\n         ELSE COALESCE(NULLIF(app_name,''),NULLIF(url,''),NULLIF(domain,''),NULLIF(ip,''),NULLIF(bundle_id,''),'asset #'||id::text) END,\n    concat_ws(' · ',type,NULLIF(page_title,''),NULLIF(service_name,''),NULLIF(bundle_id,''),NULLIF(ip,''),port::text)\n  FROM assets WHERE ($1='' OR $1='asset' OR type=$1) AND\n    ($2='' OR id::text=$2 OR concat_ws(' ',domain,root_domain,ip,url,app_name,bundle_id,page_title,service_name,method) ILIKE $3)AND ($4::bigint=0 OR (id::text=$2)<$6 OR ((id::text=$2)=$6 AND (id<$4 OR (id=$4 AND type>$5))))\n  ORDER BY (id::text=$2) DESC, id DESC LIMIT 21)\n) matches ORDER BY (id::text=$2) DESC, id DESC, kind LIMIT 21",

		kind, query, pattern, after.ID, after.Kind, after.Exact)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var item ChatMention
		if err := rows.Scan(&item.Kind, &item.ID, &item.Label, &item.Description); err != nil {
			return page, err
		}
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(page.Items) > 20 {
		page.Items = page.Items[:20]
		last := page.Items[19]
		blob, _ := json.Marshal(chatMentionCursor{last.ID, last.Kind, fmt.Sprint(last.ID) == query, kind, query})
		page.NextCursor = base64.RawURLEncoding.EncodeToString(blob)
	}
	return page, nil
}

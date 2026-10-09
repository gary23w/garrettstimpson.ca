package db

import "time"

type AssetInterceptRule struct {
	ID      int64  `json:"id"`
	Enabled bool   `json:"enabled"`
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Note    string `json:"note"`
	Builtin bool   `json:"builtin"`

	Action    string    `json:"action,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const assetInterceptRuleCols = `id, enabled, kind, pattern, note, builtin, created_at, updated_at`

func scanAssetInterceptRule(row interface{ Scan(...any) error }) (AssetInterceptRule, error) {
	var r AssetInterceptRule
	err := row.Scan(&r.ID, &r.Enabled, &r.Kind, &r.Pattern, &r.Note, &r.Builtin, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

func (d *DB) ListAssetInterceptRules() ([]AssetInterceptRule, error) {
	rows, err := d.Query(`SELECT ` + assetInterceptRuleCols + ` FROM asset_intercept_rules ORDER BY builtin DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AssetInterceptRule
	for rows.Next() {
		r, err := scanAssetInterceptRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) CreateAssetInterceptRule(kind, pattern, note string, enabled bool) (AssetInterceptRule, error) {
	row := d.QueryRow(`
INSERT INTO asset_intercept_rules(enabled, kind, pattern, note, builtin)
VALUES ($1, $2, $3, $4, false)
RETURNING `+assetInterceptRuleCols,
		enabled, kind, pattern, note)
	return scanAssetInterceptRule(row)
}

func (d *DB) UpdateAssetInterceptRule(id int64, kind, pattern, note string, enabled bool) (AssetInterceptRule, error) {
	row := d.QueryRow(`
UPDATE asset_intercept_rules
   SET enabled=$2, kind=$3, pattern=$4, note=$5
WHERE id=$1
RETURNING `+assetInterceptRuleCols,
		id, enabled, kind, pattern, note)
	return scanAssetInterceptRule(row)
}

func (d *DB) DeleteAssetInterceptRule(id int64) error {
	_, err := d.Exec(`DELETE FROM asset_intercept_rules WHERE id=$1`, id)
	return err
}

func (d *DB) ToggleAssetInterceptRule(id int64, enabled bool) error {
	_, err := d.Exec(`UPDATE asset_intercept_rules SET enabled=$2 WHERE id=$1`, id, enabled)
	return err
}

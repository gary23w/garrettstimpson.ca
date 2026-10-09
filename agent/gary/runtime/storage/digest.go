package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func (s *ExplorationStore) BumpRound() (int64, error) {
	var r int64
	err := s.db.QueryRow(`UPDATE explorations SET round_no = round_no + 1 WHERE id=$1 RETURNING round_no`, s.expID).Scan(&r)
	return r, err
}

func (s *ExplorationStore) RoundNo() (int64, error) {
	var r int64
	err := s.db.QueryRow(`SELECT round_no FROM explorations WHERE id=$1`, s.expID).Scan(&r)
	return r, err
}

func (s *ExplorationStore) ColdStamps() (map[int64]*int64, error) {
	rows, err := s.db.Query(`SELECT id, cold_since_round FROM exploration_nodes
		WHERE exploration_id=$1 AND kind IN ('intent','fact')`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*int64{}
	for rows.Next() {
		var id int64
		var cs sql.NullInt64
		if err := rows.Scan(&id, &cs); err != nil {
			return nil, err
		}
		if cs.Valid {
			v := cs.Int64
			out[id] = &v
		} else {
			out[id] = nil
		}
	}
	return out, rows.Err()
}

type StampOp struct {
	ID    int64
	Set   bool
	Round int64
}

func (s *ExplorationStore) ApplyStampOps(ops []StampOp) error {
	if len(ops) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, o := range ops {
		if o.Set {
			if _, err := tx.Exec(`UPDATE exploration_nodes SET cold_since_round=$1 WHERE id=$2 AND exploration_id=$3`, o.Round, o.ID, s.expID); err != nil {
				return err
			}
		} else {
			if _, err := tx.Exec(`UPDATE exploration_nodes SET cold_since_round=NULL WHERE id=$1 AND exploration_id=$2`, o.ID, s.expID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *ExplorationStore) ContentVersions() (map[int64]int, error) {
	rows, err := s.db.Query(`SELECT id, content_version FROM exploration_nodes WHERE exploration_id=$1`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var v int
		if err := rows.Scan(&id, &v); err != nil {
			return nil, err
		}
		out[id] = v
	}
	return out, rows.Err()
}

func (s *ExplorationStore) ActiveDigests() ([]*Node, error) {
	rows, err := s.db.Query(`SELECT `+nodeCols+` FROM exploration_nodes
		WHERE exploration_id=$1 AND kind=$2 AND state=$3 ORDER BY id`, s.expID, KindDigest, StateDigestActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func (s *ExplorationStore) AddDigest(payload map[string]any, memberIDs []int64) (int64, error) {
	raw, _ := json.Marshal(payload)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var id int64
	if err := tx.QueryRow(`
INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1, $2, $3, 0, $4, 'compactor') RETURNING id`,
		s.expID, KindDigest, string(raw), StateDigestActive).Scan(&id); err != nil {
		return 0, err
	}
	for _, m := range memberIDs {
		if m == id {
			continue
		}
		if _, err := tx.Exec(`
INSERT INTO exploration_edges(exploration_id, src_id, rel, dst_id) VALUES ($1,$2,$3,$4)
ON CONFLICT (exploration_id, src_id, rel, dst_id) DO NOTHING`, s.expID, id, RelCovers, m); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

func (s *ExplorationStore) CoveredMembers() (map[int64]int64, error) {
	rows, err := s.db.Query(`
SELECT e.dst_id, e.src_id
FROM exploration_edges e
JOIN exploration_nodes d ON d.id=e.src_id AND d.exploration_id=e.exploration_id
WHERE e.exploration_id=$1 AND e.rel=$2 AND d.kind=$3 AND d.state=$4
ORDER BY e.src_id`, s.expID, RelCovers, KindDigest, StateDigestActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var member, digest int64
		if err := rows.Scan(&member, &digest); err != nil {
			return nil, err
		}
		if _, seen := out[member]; !seen {
			out[member] = digest
		}
	}
	return out, rows.Err()
}

func (s *ExplorationStore) DigestMembers(digestID int64) ([]int64, error) {
	rows, err := s.db.Query(`SELECT dst_id FROM exploration_edges
		WHERE exploration_id=$1 AND src_id=$2 AND rel=$3`, s.expID, digestID, RelCovers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, rows.Err()
}

func (s *ExplorationStore) SupersedeDigests(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM exploration_edges
			WHERE exploration_id=$1 AND src_id=$2 AND rel=$3`, s.expID, id, RelCovers); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE exploration_nodes SET state=$1 WHERE id=$2 AND exploration_id=$3 AND kind=$4`,
			StateDigestSuperseded, id, s.expID, KindDigest); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *ExplorationStore) NodeAssets(ids []int64) (map[int64][]int64, error) {
	out := map[int64][]int64{}
	if len(ids) == 0 {
		return out, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, s.expID)
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	rows, err := s.db.Query(`SELECT a.node_id, a.asset_id
		FROM exploration_anchors a
		JOIN exploration_nodes n ON n.id=a.node_id
		WHERE n.exploration_id=$1 AND a.node_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var node, asset int64
		if err := rows.Scan(&node, &asset); err != nil {
			return nil, err
		}
		out[node] = append(out[node], asset)
	}
	return out, rows.Err()
}

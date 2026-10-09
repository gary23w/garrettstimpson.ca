package db

import (
	"database/sql"
	"strings"
	"time"
)

type SkillUsage struct {
	Skill         string `json:"skill"`
	AgentKey      string `json:"agent_key"`
	TaskID        int64  `json:"task_id"`
	ExplorationID int64  `json:"exploration_id"`
	IntentID      int64  `json:"intent_id"`
	SessionID     string `json:"session_id"`
	ArgsLen       int    `json:"args_len"`
	Found         bool   `json:"found"`
}

func (d *DB) InsertSkillUsage(u *SkillUsage) error {
	_, err := d.Exec(`
INSERT INTO skill_usage(skill, agent_key, task_id, exploration_id, intent_id, session_id, args_len, found)
VALUES ($1, NULLIF($2,''), $3, $4, $5, NULLIF($6,''), $7, $8)`,
		u.Skill, u.AgentKey, nullIfZero(u.TaskID), nullIfZero(u.ExplorationID),
		nullIfZero(u.IntentID), u.SessionID, u.ArgsLen, u.Found)
	return err
}

func nullIfZero(v int64) any {
	if v > 0 {
		return v
	}
	return nil
}

type SkillStat struct {
	Skill    string     `json:"skill"`
	Calls    int        `json:"calls"`
	Tasks    int        `json:"tasks"`
	Agents   []string   `json:"agents"`
	LastUsed *time.Time `json:"last_used"`
}

func (d *DB) SkillStats() ([]SkillStat, error) {

	rows, err := d.Query(`
SELECT skill, COUNT(*) AS calls,
       COUNT(DISTINCT task_id) AS tasks,
       COALESCE(STRING_AGG(DISTINCT agent_key, ','), '') AS agents,
       MAX(ts) AS last_used
FROM skill_usage
WHERE found
GROUP BY skill
ORDER BY COUNT(*) DESC, skill`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SkillStat{}
	for rows.Next() {
		var s SkillStat
		var agents string
		var lastUsed sql.NullTime
		if err := rows.Scan(&s.Skill, &s.Calls, &s.Tasks, &agents, &lastUsed); err != nil {
			return nil, err
		}
		s.Agents = []string{}
		if agents != "" {
			s.Agents = strings.Split(agents, ",")
		}
		if lastUsed.Valid {
			t := lastUsed.Time
			s.LastUsed = &t
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	return mergeArchivedSkillStats(out, archived, false), nil
}

func (d *DB) MissingSkillStats(limit int) ([]SkillStat, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := d.Query(`
SELECT skill, COUNT(*) AS calls,
       COALESCE(STRING_AGG(DISTINCT agent_key, ','), '') AS agents,
       MAX(ts) AS last_used
FROM skill_usage
WHERE NOT found
GROUP BY skill
ORDER BY COUNT(*) DESC, skill`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SkillStat{}
	for rows.Next() {
		var s SkillStat
		var agents string
		var lastUsed sql.NullTime
		if err := rows.Scan(&s.Skill, &s.Calls, &agents, &lastUsed); err != nil {
			return nil, err
		}
		s.Agents = []string{}
		if agents != "" {
			s.Agents = strings.Split(agents, ",")
		}
		if lastUsed.Valid {
			t := lastUsed.Time
			s.LastUsed = &t
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	out = mergeArchivedSkillStats(out, archived, true)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

type SkillCall struct {
	TS        time.Time `json:"ts"`
	AgentKey  string    `json:"agent_key"`
	TaskID    int64     `json:"task_id"`
	SessionID string    `json:"session_id"`
	ArgsLen   int       `json:"args_len"`
}

func (d *DB) RecentSkillCalls(skill string, limit int) ([]SkillCall, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.Query(`
SELECT ts, COALESCE(agent_key,''), COALESCE(task_id,0), COALESCE(session_id,''), args_len
FROM skill_usage
WHERE skill = $1 AND found
ORDER BY ts DESC
LIMIT $2`, skill, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SkillCall{}
	for rows.Next() {
		var c SkillCall
		if err := rows.Scan(&c.TS, &c.AgentKey, &c.TaskID, &c.SessionID, &c.ArgsLen); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) SkillCallsByTask(taskID int64) ([]SkillStat, error) {
	rows, err := d.Query(`
SELECT skill, COUNT(*) AS calls, MAX(ts) AS last_used
FROM skill_usage
WHERE task_id = $1 AND found
GROUP BY skill
ORDER BY COUNT(*) DESC, skill`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SkillStat{}
	for rows.Next() {
		var s SkillStat
		var lastUsed sql.NullTime
		if err := rows.Scan(&s.Skill, &s.Calls, &lastUsed); err != nil {
			return nil, err
		}
		s.Agents = []string{}
		if lastUsed.Valid {
			t := lastUsed.Time
			s.LastUsed = &t
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

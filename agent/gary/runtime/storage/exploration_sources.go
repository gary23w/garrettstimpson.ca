package db

import (
	"database/sql"
	"sort"
)

type DirectSourceStore struct {
	Task  TaskSource
	Store *ExplorationStore
}

func (s *ExplorationStore) DirectSourceStores() ([]DirectSourceStore, error) {
	rows, err := s.db.Query(`
SELECT source.id, source.exploration_id, source.description, source.goal, source.status
FROM tasks owner
JOIN task_relations relation ON relation.task_id=owner.id
JOIN tasks source ON source.id=relation.source_task_id AND source.deleted_at IS NULL
WHERE owner.exploration_id=$1 AND owner.deleted_at IS NULL
ORDER BY relation.created_at, source.id`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DirectSourceStore{}
	for rows.Next() {
		var source TaskSource
		if err := rows.Scan(&source.TaskID, &source.ExplorationID, &source.Description, &source.Goal, &source.Status); err != nil {
			return nil, err
		}
		out = append(out, DirectSourceStore{Task: source, Store: s.db.Exploration(source.ExplorationID)})
	}
	return out, rows.Err()
}

func (s *ExplorationStore) TaskID() (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1 AND deleted_at IS NULL`, s.expID).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return id, nil
}

func markInheritedNode(n *Node, taskID int64) *Node {
	if n == nil {
		return nil
	}
	n.SourceTaskID = taskID
	n.Inherited = true
	return n
}

func markInheritedActivities(in []Activity, taskID int64) []Activity {
	for i := range in {
		in[i].SourceTaskID = taskID
		in[i].Inherited = true
	}
	return in
}

func inheritedIntentTerminal(state string) bool {
	switch state {
	case "done", "blocked", "exhausted", "stopped":
		return true
	default:
		return false
	}
}

func (s *ExplorationStore) ListByKindWithSources(kind string, limit int) ([]*Node, error) {
	out, err := s.ListByKind(kind, limit)
	if err != nil {
		return nil, err
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		nodes, err := source.Store.ListByKind(kind, limit)
		if err != nil {
			return nil, err
		}
		for _, node := range nodes {
			if kind == KindIntent && !inheritedIntentTerminal(node.State) {
				continue
			}
			out = append(out, markInheritedNode(node, source.Task.TaskID))
		}
	}
	return out, nil
}

func (s *ExplorationStore) ListByKindPageWithSources(kind string, before int64, limit int, q string) (nodes []*Node, hasMore bool, total int, err error) {
	if limit <= 0 {
		limit = 20
	}
	own, err := s.listByKindPageFiltered(kind, before, limit, q)
	if err != nil {
		return nil, false, 0, err
	}
	merged := own
	total, err = s.countByKindFiltered(kind, q)
	if err != nil {
		return nil, false, 0, err
	}

	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, false, 0, err
	}
	for _, source := range sources {
		page, err := source.Store.listByKindPageFiltered(kind, before, limit, q)
		if err != nil {
			return nil, false, 0, err
		}
		for _, n := range page {
			merged = append(merged, markInheritedNode(n, source.Task.TaskID))
		}
		cnt, err := source.Store.countByKindFiltered(kind, q)
		if err != nil {
			return nil, false, 0, err
		}
		total += cnt
	}

	sort.Slice(merged, func(i, j int) bool { return merged[i].ID > merged[j].ID })
	hasMore = len(merged) > limit
	if hasMore {
		merged = merged[:limit]
	}
	return merged, hasMore, total, nil
}

func (s *ExplorationStore) GetNodeWithSources(id int64) (*Node, error) {
	node, err := s.GetNode(id)
	if err != nil || node != nil {
		return node, err
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		node, err = source.Store.GetNode(id)
		if err != nil {
			return nil, err
		}
		if node != nil {
			if node.Kind == KindIntent && !inheritedIntentTerminal(node.State) {
				continue
			}
			return markInheritedNode(node, source.Task.TaskID), nil
		}
	}
	return nil, nil
}

func (s *ExplorationStore) FindingIntentsWithSources() (map[int64]int64, error) {
	out, err := s.FindingIntents()
	if err != nil {
		return nil, err
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		items, err := source.Store.FindingIntentsTerminal()
		if err != nil {
			return nil, err
		}
		for findingID, intentID := range items {
			out[findingID] = intentID
		}
	}
	return out, nil
}

func (s *ExplorationStore) ActivityTraceWithSources(nodeID int64, limit int) ([]Activity, error) {
	acts, err := s.ActivityTrace(nodeID, limit)
	if err != nil || len(acts) > 0 {
		return acts, err
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		node, nodeErr := source.Store.GetNode(nodeID)
		if nodeErr != nil {
			return nil, nodeErr
		}
		if node == nil || node.Kind != KindIntent {
			continue
		}
		acts, err = source.Store.ActivityTraceForTerminalIntent(nodeID, limit)
		if err != nil {
			return nil, err
		}
		if len(acts) > 0 {
			return markInheritedActivities(acts, source.Task.TaskID), nil
		}
	}
	return []Activity{}, nil
}

func (s *ExplorationStore) ActivityListWithSources(nodeID, sinceID int64, limit int) ([]Activity, int64, error) {
	node, err := s.GetNode(nodeID)
	if err != nil {
		return nil, sinceID, err
	}
	if node != nil {
		return s.ActivityList(&nodeID, sinceID, limit)
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, sinceID, err
	}
	for _, source := range sources {
		node, err = source.Store.GetNode(nodeID)
		if err != nil {
			return nil, sinceID, err
		}
		if node == nil || node.Kind != KindIntent {
			continue
		}
		acts, cursor, err := source.Store.ActivityListForTerminalIntent(nodeID, sinceID, limit)
		if err != nil {
			return nil, sinceID, err
		}
		return markInheritedActivities(acts, source.Task.TaskID), cursor, nil
	}
	return []Activity{}, sinceID, nil
}

func (s *ExplorationStore) ActivityDetailWithSources(id int64) (string, error) {
	detail, err := s.ActivityDetail(id)
	if err != nil || detail != "" {
		return detail, err
	}
	acts, err := s.ActivityByIDsWithSources([]int64{id})
	if err != nil || len(acts) == 0 {
		return "", err
	}
	return acts[0].Detail, nil
}

func (s *ExplorationStore) ActivityTraceSearchWithSources(nodeID int64, q string, limit int) ([]Activity, error) {
	acts, err := s.ActivityTraceSearch(&nodeID, q, limit)
	if err != nil || len(acts) > 0 {
		return acts, err
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		node, nodeErr := source.Store.GetNode(nodeID)
		if nodeErr != nil {
			return nil, nodeErr
		}
		if node == nil || node.Kind != KindIntent {
			continue
		}
		acts, err = source.Store.ActivityTraceSearchForTerminalIntent(nodeID, q, limit)
		if err != nil {
			return nil, err
		}
		if len(acts) > 0 {
			return markInheritedActivities(acts, source.Task.TaskID), nil
		}
	}
	return []Activity{}, nil
}

func (s *ExplorationStore) ActivityTraceSearchAllWithSources(excludeNodeID int64, q string, limit int) ([]Activity, error) {
	if limit <= 0 {
		limit = 100
	}
	out, err := s.ActivityTraceSearchExcluding(excludeNodeID, q, limit)
	if err != nil {
		return nil, err
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		acts, err := source.Store.ActivityTraceSearchTerminalIntents(q, limit)
		if err != nil {
			return nil, err
		}
		out = append(out, markInheritedActivities(acts, source.Task.TaskID)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *ExplorationStore) ActivityByIDsWithSources(ids []int64) ([]Activity, error) {
	out, err := s.ActivityByIDs(ids)
	if err != nil {
		return nil, err
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		acts, err := source.Store.ActivityByIDsForTerminalIntents(ids)
		if err != nil {
			return nil, err
		}
		out = append(out, markInheritedActivities(acts, source.Task.TaskID)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *ExplorationStore) AssetRefsWithSources(assetID int64) ([]AssetRef, error) {
	out, err := s.AssetRefs(assetID)
	if err != nil {
		return nil, err
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		refs, err := source.Store.AssetRefs(assetID)
		if err != nil {
			return nil, err
		}
		for i := range refs {
			if refs[i].Kind == KindIntent && !inheritedIntentTerminal(refs[i].State) {
				continue
			}
			refs[i].SourceTaskID = source.Task.TaskID
			refs[i].Inherited = true
			out = append(out, refs[i])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

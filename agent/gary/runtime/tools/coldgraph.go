package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/storage"
)

type cgNode struct {
	ID    int64
	Kind  string
	State string
}

type cgEdge struct {
	From int64
	Rel  string
	To   int64
}

type coldParams struct {
	R int
	K int
}

func defaultColdParams() coldParams { return coldParams{R: 6, K: 2} }

type coldGraph struct {
	nodes    map[int64]cgNode
	children map[int64][]int64
	parents  map[int64][]int64
}

func newColdGraph(nodes []cgNode, edges []cgEdge) *coldGraph {
	g := &coldGraph{
		nodes:    make(map[int64]cgNode, len(nodes)),
		children: map[int64][]int64{},
		parents:  map[int64][]int64{},
	}
	for _, n := range nodes {
		g.nodes[n.ID] = n
	}
	for _, e := range edges {
		if e.Rel == db.RelCovers {
			continue
		}
		if _, ok := g.nodes[e.From]; !ok {
			continue
		}
		if _, ok := g.nodes[e.To]; !ok {
			continue
		}
		g.children[e.From] = append(g.children[e.From], e.To)
		g.parents[e.To] = append(g.parents[e.To], e.From)
	}
	return g
}

func isLiveIntent(n cgNode) bool {
	if n.Kind != db.KindIntent {
		return false
	}
	switch n.State {
	case "open", "running", "paused":
		return true
	}
	return false
}

func foldableKind(k string) bool { return k == db.KindIntent || k == db.KindFact }

func (g *coldGraph) hotSet() map[int64]bool {
	hot := map[int64]bool{}
	var stack []int64
	for _, n := range g.nodes {
		if isLiveIntent(n) {
			stack = append(stack, n.ID)
		}
	}

	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if hot[id] {
			continue
		}
		hot[id] = true
		stack = append(stack, g.parents[id]...)
	}

	for _, n := range g.nodes {
		if isLiveIntent(n) {
			for _, c := range g.children[n.ID] {
				hot[c] = true
			}
		}
	}
	return hot
}

func (g *coldGraph) structuralCold(hot map[int64]bool) map[int64]bool {
	cold := map[int64]bool{}
	for id, n := range g.nodes {
		if foldableKind(n.Kind) && !hot[id] {
			cold[id] = true
		}
	}
	return cold
}

type stampOp struct {
	ID    int64
	Set   bool
	Round int64
}

func computeStampOps(structCold map[int64]bool, coldSince map[int64]*int64, roundNo int64) []stampOp {
	var ops []stampOp
	seen := map[int64]bool{}
	for id := range structCold {
		seen[id] = true
		if coldSince[id] == nil {
			ops = append(ops, stampOp{ID: id, Set: true, Round: roundNo})
		}
	}

	for id, cs := range coldSince {
		if cs != nil && !seen[id] {
			ops = append(ops, stampOp{ID: id, Set: false})
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].ID < ops[j].ID })
	return ops
}

func (g *coldGraph) eligibleCold(structCold map[int64]bool, coldSince map[int64]*int64, roundNo int64, p coldParams) map[int64]bool {
	out := map[int64]bool{}
	for id := range structCold {
		if cs := coldSince[id]; cs != nil && roundNo-*cs >= int64(p.R) {
			out[id] = true
		}
	}
	return out
}

type block struct {
	Members []int64
	Anchors []int64
}

func (g *coldGraph) group(set map[int64]bool, p coldParams) []block {
	uf := newUnionFind(set)

	for from := range set {
		for _, to := range g.children[from] {
			if set[to] {
				uf.union(from, to)
			}
		}
	}

	comps := uf.components()
	byParent := map[int64][]int64{}
	for _, ids := range comps {
		if len(ids) != 1 {
			continue
		}
		s := ids[0]
		for _, par := range g.parents[s] {
			if g.nodes[par].Kind == db.KindDigest {
				continue
			}
			byParent[par] = append(byParent[par], s)
		}
	}
	for _, sibs := range byParent {
		if len(sibs) < 2 {
			continue
		}
		for i := 1; i < len(sibs); i++ {
			uf.union(sibs[0], sibs[i])
		}
	}

	comps = uf.components()
	var blocks []block
	for _, ids := range comps {
		if len(ids) < p.K {
			continue
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		memberSet := make(map[int64]bool, len(ids))
		for _, m := range ids {
			memberSet[m] = true
		}
		anchorSet := map[int64]bool{}
		for _, m := range ids {
			for _, par := range g.parents[m] {
				if memberSet[par] {
					continue
				}
				pn, ok := g.nodes[par]
				if !ok || pn.Kind == db.KindDigest {
					continue
				}
				anchorSet[par] = true
			}
		}
		anchors := make([]int64, 0, len(anchorSet))
		for a := range anchorSet {
			anchors = append(anchors, a)
		}
		sort.Slice(anchors, func(i, j int) bool { return anchors[i] < anchors[j] })
		blocks = append(blocks, block{Members: ids, Anchors: anchors})
	}

	sort.Slice(blocks, func(i, j int) bool { return blocks[i].Members[0] < blocks[j].Members[0] })
	return blocks
}

func blockSignature(b block, contentVer map[int64]int) string {
	h := sha256.New()
	for _, m := range b.Members {
		fmt.Fprintf(h, "m:%d:%d;", m, contentVer[m])
	}
	for _, a := range b.Anchors {
		fmt.Fprintf(h, "a:%d:%d;", a, contentVer[a])
	}
	return hex.EncodeToString(h.Sum(nil))
}

type unionFind struct{ parent map[int64]int64 }

func newUnionFind(set map[int64]bool) *unionFind {
	uf := &unionFind{parent: make(map[int64]int64, len(set))}
	for id := range set {
		uf.parent[id] = id
	}
	return uf
}

func (u *unionFind) find(x int64) int64 {
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]]
		x = u.parent[x]
	}
	return x
}

func (u *unionFind) union(a, b int64) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[ra] = rb
	}
}

func (u *unionFind) components() map[int64][]int64 {
	out := map[int64][]int64{}
	for id := range u.parent {
		r := u.find(id)
		out[r] = append(out[r], id)
	}
	return out
}

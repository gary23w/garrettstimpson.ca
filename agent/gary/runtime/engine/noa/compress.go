package noa

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

type CompressRange struct {
	StartRef string
	EndRef   string
	Summary  string
	Topic    string

	SummaryMaxChars *int
}

type ApplyInput struct {
	Ranges []CompressRange

	Messages []CoreMessage
	State    CompressionState
	Config   Config

	CallID string

	Archiver Archiver

	CreatedAt string

	Now int64

	CountTokens TokenCountFn
}

type ApplyResult struct {
	State            CompressionState
	BlocksCreated    []CompressionBlock
	TokensCompressed int
	Errors           []string
	Warnings         []string

	SurvivingBlockIDs []string
}

type rangeEntry struct {
	req      CompressRange
	resolved ResolvedRange
	err      *BoundaryNotFoundError
	skipped  bool
}

func jsLen(s string) int { return utf8.RuneCountInString(s) }

func ApplyCompression(in ApplyInput) ApplyResult {
	ensureMaps(&in.State)
	res := ApplyResult{State: in.State}
	if len(in.Ranges) == 0 {
		return res
	}
	if in.Archiver == nil {
		res.Errors = append(res.Errors, "internal: no archiver configured; refusing to compress without a durable copy of the originals")
		return res
	}
	count := in.CountTokens
	if count == nil {
		count = DefaultCountTokens
	}

	entries := make([]rangeEntry, len(in.Ranges))
	var unknownCount, consumedCount, resolvable int
	for i, r := range in.Ranges {
		rr, err := ResolveBoundaries(r.StartRef, r.EndRef, in.Messages, in.State)
		entries[i] = rangeEntry{req: r, resolved: rr, err: err}
		switch {
		case err == nil:
			resolvable++
			res.Warnings = append(res.Warnings, rr.Warnings...)
		case err.Kind == NotFoundUnknown, err.Kind == NotFoundInvalid:
			unknownCount++
		case err.Kind == NotFoundConsumed:
			consumedCount++
		}
	}

	order := make([]int, 0, len(entries))
	for i, e := range entries {
		if e.err == nil {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(a, b int) bool {
		return entries[order[a]].resolved.StartIndex < entries[order[b]].resolved.StartIndex
	})
	acceptedMax := -1
	for _, i := range order {
		if entries[i].resolved.StartIndex <= acceptedMax {
			entries[i].skipped = true
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"Skipped range (%s..%s) — overlaps an earlier range in the batch; the earlier range takes precedence. Keep ranges disjoint.",
				entries[i].req.StartRef, entries[i].req.EndRef))
			continue
		}
		if entries[i].resolved.EndIndex > acceptedMax {
			acceptedMax = entries[i].resolved.EndIndex
		}
	}

	if msg, rejected := checkSizeGate(entries, in, count, unknownCount, consumedCount, resolvable); rejected {
		res.Errors = append(res.Errors, msg)
		return res
	}

	working := CloneState(in.State)
	preExisting := CoveredMessageIDs(in.State)
	type pending struct {
		block   CompressionBlock
		content []byte
	}
	var built []pending

	for i := range entries {
		e := &entries[i]
		if e.err != nil {
			res.Errors = append(res.Errors, e.err.Error())
			continue
		}
		if e.skipped {
			continue
		}
		blk, content, warns, surviving, err := buildBlock(e.req, e.resolved, &working, in, count, preExisting)
		res.Warnings = append(res.Warnings, warns...)
		for _, id := range surviving {
			if !containsString(res.SurvivingBlockIDs, id) {
				res.SurvivingBlockIDs = append(res.SurvivingBlockIDs, id)
			}
		}
		if err != nil {
			res.Errors = append(res.Errors, err.Error())
			continue
		}
		built = append(built, pending{block: blk, content: content})
	}
	if len(built) == 0 {
		return res
	}

	var writtenPaths []string
	for i := range built {
		b := &built[i].block
		abs, rel, err := in.Archiver.Write(b.Tier, b.BlockID, b.StartRef, b.EndRef, built[i].content)
		if err != nil {
			for _, p := range writtenPaths {
				_ = in.Archiver.Remove(p)
			}
			res.Errors = append(res.Errors, fmt.Sprintf(
				"Failed to archive %s: %v. No blocks were created — the originals must be on disk before they leave the context.",
				b.BlockID, err))
			return ApplyResult{State: in.State, Errors: res.Errors, Warnings: res.Warnings}
		}
		b.ArchivePath, b.ArchiveRel = abs, rel
		writtenPaths = append(writtenPaths, abs)
	}

	for _, p := range built {
		working.Blocks = append(working.Blocks, p.block)
		res.BlocksCreated = append(res.BlocksCreated, p.block)
		res.TokensCompressed += p.block.CompressedTokens
		for _, id := range p.block.DirectBlockIDs {
			if cb := FindBlock(&working, id); cb != nil {
				cb.Active = false
			}
		}
	}
	working.Stats.CompressionCount += len(res.BlocksCreated)
	working.Stats.TokensCompressed += res.TokensCompressed

	working.Nudge.LastPerMessageNudgeTokens = 0
	working.Nudge.LastNudgeShownTokens = 0
	working.Nudge.LastShownByTier = map[Tier]int{}

	res.State = working
	return res
}

func checkSizeGate(entries []rangeEntry, in ApplyInput, count TokenCountFn,
	unknownCount, consumedCount, resolvable int) (string, bool) {
	minChars := in.Config.Compress.MinCompressRange
	if minChars <= 0 {
		return "", false
	}

	totalChars := 0
	hasBlockBoundary := false
	for _, e := range entries {
		if e.err != nil || e.skipped {
			continue
		}
		if e.resolved.Kind == BoundaryBlock {

			hasBlockBoundary = true
			continue
		}
		for _, id := range e.resolved.MessageIDs {
			if m := findMessage(in.Messages, id); m != nil {
				totalChars += jsLen(m.Text)
			}
		}
	}
	if hasBlockBoundary || totalChars >= minChars {
		return "", false
	}

	switch {
	case resolvable == 0 && consumedCount == 0 && unknownCount > 0:
		return fmt.Sprintf(
			"None of the %d requested range(s) resolved — every ref is unknown to this session. "+
				"Refs are per-session snapshots, assigned once when a message is first rendered; no compression "+
				"reassigns them, so an unknown ref cannot have come from an earlier compression here. "+
				"Use the refs shown in the <noa-ref> tags of the current context. %s",
			len(in.Ranges), refGateDiagnostics(in.State, len(in.Ranges), unknownCount)), true
	case consumedCount > 0:
		return fmt.Sprintf(
			"Every requested range is already compressed — its content is covered by an active block. %s %s",
			liveHint(in.State), refGateDiagnostics(in.State, len(in.Ranges), unknownCount)), true
	default:
		n := 0
		for _, e := range entries {
			if e.err == nil && !e.skipped {
				n++
			}
		}
		return fmt.Sprintf(
			"Total compressible content too small (%d chars across %d range(s), min %d). "+
				"Combine more messages into fewer, larger ranges.",
			totalChars, n, minChars), true
	}
}

func refGateDiagnostics(state CompressionState, requested, unknown int) string {
	highest := HighestUsedIndex(state.MessageRefs)
	return fmt.Sprintf("[diagnostics: session highest ref=%s, unknown ranges in request=%d/%d, session history=%d compression(s), %d block(s)]",
		IndexToRef(max(highest, 1)), unknown, requested, state.Stats.CompressionCount, len(state.Blocks))
}

func liveHint(state CompressionState) string {
	active := ActiveBlocks(state)
	if len(active) == 0 {
		return ""
	}
	return fmt.Sprintf("Active blocks: %s..%s.", active[0].BlockID, active[len(active)-1].BlockID)
}

func findMessage(msgs []CoreMessage, id string) *CoreMessage {
	for i := range msgs {
		if msgs[i].ID == id {
			return &msgs[i]
		}
	}
	return nil
}

func buildBlock(req CompressRange, r ResolvedRange, state *CompressionState, in ApplyInput,
	count TokenCountFn, preExisting map[string]bool) (CompressionBlock, []byte, []string, []string, error) {

	var warnings []string
	var surviving []string
	msgs := in.Messages
	cfg := in.Config

	start, end := r.StartIndex, r.EndIndex
	messageIDs := r.MessageIDs
	nested := r.NestedBlockIDs
	if r.Kind == BoundaryMessage {
		ns, ne := ApplyPairBoundaryAdjustments(start, end, msgs)
		if ns != start || ne != end {
			start, end = ns, ne
			messageIDs = messageIDs[:0]
			for i := start; i <= end && i < len(msgs); i++ {
				if msgs[i].ID != "" && !isRenderedSummaryMessage(msgs[i]) {
					messageIDs = append(messageIDs, msgs[i].ID)
				}
			}
			rc := newResolveContext(msgs, *state)
			nested = nestedActiveBlocks(rc, start, end)
		}
	}
	adjusted := ResolvedRange{StartIndex: start, EndIndex: end, Kind: r.Kind,
		MessageIDs: messageIDs, NestedBlockIDs: nested}

	tier := DecideTier(adjusted, *state, cfg)
	surviving = tier.SurvivingBlockIDs

	effective := map[string]bool{}
	for _, id := range messageIDs {
		effective[id] = true
	}
	var consumedBlocks []CompressionBlock
	for _, id := range tier.ConsumedBlockIDs {
		b := FindBlock(state, id)
		if b == nil {
			continue
		}
		consumedBlocks = append(consumedBlocks, *b)
		for _, mid := range b.EffectiveMessageIDs {
			effective[mid] = true
		}
	}

	direct := map[string]bool{}
	for id := range effective {
		if !preExisting[id] {
			direct[id] = true
		}
	}

	protectedCallIDs := collectProtectedToolCallIDs(msgs, cfg)
	for id := range direct {
		m := findMessage(msgs, id)
		if m != nil && isMessageProtectedWithPairing(*m, cfg, protectedCallIDs) {
			delete(direct, id)
			delete(effective, id)
		}
	}

	protectedRefs := ComputeProtectedRefs(msgs, *state, cfg)
	var hitProtected []string
	for id := range direct {
		if ref, ok := state.MessageRefs.ByRaw[id]; ok && protectedRefs[ref] {
			hitProtected = append(hitProtected, ref)
			delete(direct, id)
			delete(effective, id)
		}
	}
	if len(hitProtected) > 0 {
		sort.Strings(hitProtected)
		if len(direct) == 0 && len(consumedBlocks) == 0 {
			return CompressionBlock{}, nil, warnings, surviving, fmt.Errorf(
				"Range is entirely within the protected zone (the last %d messages and/or the most recent user message): %s. "+
					"Adjust startId/endId to older messages.",
				cfg.PreserveRecentMessages, strings.Join(hitProtected, ", "))
		}
		warnings = append(warnings, fmt.Sprintf(
			"Excluded %d protected message(s) %s from compression range (recent/last-user zone).",
			len(hitProtected), strings.Join(hitProtected, ", ")))
	}

	kept, withdrawn := WithdrawSplitTurns(msgs, direct)
	if len(withdrawn) > 0 {
		direct = kept
		for _, id := range withdrawn {
			delete(effective, id)
		}
		if len(direct) == 0 && len(consumedBlocks) == 0 {
			return CompressionBlock{}, nil, warnings, surviving, fmt.Errorf(
				"Range would split a turn at the protected-zone boundary: a visible tool-call must keep its reasoning run " +
					"(strict-echo providers reject a rebuilt request that lost it). Shrink the range to end before the turn starts, " +
					"or wait until the whole turn ages out of the protected zone.")
		}
		warnings = append(warnings, fmt.Sprintf(
			"Withdrew %d message(s) to keep turn(s) intact (a visible tool-call would have lost its reasoning run).",
			len(withdrawn)))
	}

	if r.Kind != BoundaryBlock && len(direct) == 0 && len(consumedBlocks) > 0 {
		return CompressionBlock{}, nil, warnings, surviving, fmt.Errorf(
			"Range contains no new content — it is already covered by blocks %s..%s. "+
				"To consolidate them, pass their block ids as startId/endId instead.",
			consumedBlocks[0].BlockID, consumedBlocks[len(consumedBlocks)-1].BlockID)
	}

	if IsTerminalRewrite(tier, len(direct), cfg) {
		maxT := cfg.Tiers.MaxTier
		return CompressionBlock{}, nil, warnings, surviving, fmt.Errorf(
			"Tier %d is the terminal layer — re-summarizing T%d blocks into another T%d block reclaims nothing. "+
				"Compress a lower tier, or include new uncompressed messages in the range.", maxT, maxT, maxT)
	}

	if err := validateSummary(req, cfg, len(direct), len(consumedBlocks)); err != nil {
		return CompressionBlock{}, nil, warnings, surviving, err
	}

	compressed := 0
	for id := range direct {
		if m := findMessage(msgs, id); m != nil {
			compressed += CountMessageTokens(*m, count)
		}
	}
	for _, b := range consumedBlocks {
		compressed += count(b.Summary)
	}

	effIDs := sortedByRef(effective, state.MessageRefs)
	directIDs := sortedByRef(direct, state.MessageRefs)
	startRef, endRef := refSpan(effIDs, state.MessageRefs)
	if startRef == "" {
		startRef, endRef = req.StartRef, req.EndRef
	}

	topic := req.Topic
	blk := CompressionBlock{
		BlockID:             AllocateBlockID(state),
		Tier:                tier.OutputTier,
		Topic:               topic,
		Summary:             req.Summary,
		DirectMessageIDs:    directIDs,
		EffectiveMessageIDs: effIDs,
		DirectBlockIDs:      tier.ConsumedBlockIDs,
		CompressedTokens:    compressed,
		StartRef:            startRef,
		EndRef:              endRef,
		CreatedAt:           in.Now,
		Active:              true,
		CompressCallID:      in.CallID,
	}

	content := RenderArchive(ArchiveRenderInput{
		BlockID:        blk.BlockID,
		Tier:           blk.Tier,
		SessionID:      state.SessionID,
		CreatedAt:      in.CreatedAt,
		StartRef:       startRef,
		EndRef:         endRef,
		Topic:          topic,
		Summary:        req.Summary,
		Entries:        archiveEntries(msgs, start, end, direct, consumedBlocks, *state),
		OriginalTokens: compressed,
	})
	return blk, content, warnings, surviving, nil
}

func validateSummary(req CompressRange, cfg Config, directCount, consumedCount int) error {
	s := strings.TrimSpace(req.Summary)
	if s == "" {
		return fmt.Errorf("Summary is empty — provide a meaningful summary of the compressed range.")
	}
	n := jsLen(s)
	if n < cfg.Compress.MinSummaryLength {
		return fmt.Errorf("Summary too short (%d chars, min %d). A summary this brief cannot stand in for the content it replaces.",
			n, cfg.Compress.MinSummaryLength)
	}
	maxChars := cfg.Compress.MaxSummaryLength
	if req.SummaryMaxChars != nil && *req.SummaryMaxChars > 0 {
		maxChars = *req.SummaryMaxChars
	}
	if n > maxChars {
		return fmt.Errorf("Summary too long (%d chars, max %d). Strip noise — keep critical paths, decisions, errors, and code references. "+
			"Or pass summaryMaxChars to increase the limit — don't lose critical info just to fit.", n, maxChars)
	}
	if directCount == 0 && consumedCount == 0 {
		return fmt.Errorf("Range contains no compressible messages — all are already covered by active blocks or protected.")
	}
	return nil
}

func archiveEntries(msgs []CoreMessage, start, end int, direct map[string]bool,
	consumed []CompressionBlock, state CompressionState) []ArchiveEntry {

	byID := make(map[string]CompressionBlock, len(consumed))
	for _, b := range consumed {
		byID[b.BlockID] = b
	}
	var out []ArchiveEntry
	for i := start; i <= end && i < len(msgs); i++ {
		m := msgs[i]
		if bid, ok := BlockIDFromSummaryID(m.ID); ok {
			if b, absorbed := byID[bid]; absorbed {
				blk := b
				out = append(out, ArchiveEntry{Block: &blk})
			}

			continue
		}
		if !direct[m.ID] {
			continue
		}
		cm := m
		out = append(out, ArchiveEntry{Message: &cm, Ref: state.MessageRefs.ByRaw[m.ID]})
	}
	return out
}

func sortedByRef(set map[string]bool, refs MessageRefMap) []string {
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.SliceStable(out, func(a, b int) bool {
		return refIndexOf(out[a], refs) < refIndexOf(out[b], refs)
	})
	return out
}

func refIndexOf(id string, refs MessageRefMap) int {
	ref, ok := refs.ByRaw[id]
	if !ok || ref == BlockedRef {
		return MaxRefIndex + 1
	}
	n, ok := RefToIndex(ref)
	if !ok {
		return MaxRefIndex + 1
	}
	return n
}

func refSpan(ids []string, refs MessageRefMap) (string, string) {
	lo, hi := "", ""
	loN, hiN := MaxRefIndex+1, -1
	for _, id := range ids {
		ref, ok := refs.ByRaw[id]
		if !ok || ref == BlockedRef {
			continue
		}
		n, ok := RefToIndex(ref)
		if !ok {
			continue
		}
		if n < loN {
			loN, lo = n, ref
		}
		if n > hiN {
			hiN, hi = n, ref
		}
	}
	return lo, hi
}

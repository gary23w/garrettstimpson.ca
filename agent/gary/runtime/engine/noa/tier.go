package noa

type TierDecision struct {
	TargetTier Tier

	OutputTier Tier

	ConsumedBlockIDs []string

	SurvivingBlockIDs []string
}

func DecideTier(r ResolvedRange, state CompressionState, cfg Config) TierDecision {
	maxTier := cfg.Tiers.MaxTier
	if maxTier < 2 {
		maxTier = 3
	}

	d := TierDecision{TargetTier: 1, OutputTier: 1}
	if r.Kind != BoundaryBlock {

		return d
	}

	lowest := Tier(0)
	for _, id := range r.NestedBlockIDs {
		b := FindBlock(&state, id)
		if b == nil || !b.Active {
			continue
		}
		if lowest == 0 || b.Tier < lowest {
			lowest = b.Tier
		}
	}
	if lowest > 0 {
		d.TargetTier = lowest
	}
	d.OutputTier = min(maxTier, d.TargetTier+1)

	for _, id := range r.NestedBlockIDs {
		b := FindBlock(&state, id)
		if b == nil || !b.Active {
			continue
		}
		if b.Tier == d.TargetTier {
			d.ConsumedBlockIDs = append(d.ConsumedBlockIDs, id)
		} else {
			d.SurvivingBlockIDs = append(d.SurvivingBlockIDs, id)
		}
	}
	return d
}

func IsTerminalRewrite(d TierDecision, directCount int, cfg Config) bool {
	maxTier := cfg.Tiers.MaxTier
	if maxTier < 2 {
		maxTier = 3
	}
	return d.TargetTier == maxTier && directCount == 0
}

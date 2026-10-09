package noa

import "fmt"

type TierConfig struct {
	Enabled bool

	MaxTier Tier

	Tier2Trigger int

	Tier3Trigger int
}

type NudgeConfig struct {
	MaxContextLimitPct float64

	MinContextLimitPct float64

	EmergencyThresholdPct float64

	GrowthRatio float64
	GrowthFloor int
	GrowthCap   int

	MinGrowthFloor int
	MinGrowthRatio float64

	Tier2GrowthMultiplier float64

	MinPressureBenefitTokens *int
}

type TruncateConfig struct {
	Threshold float64
}

type CompressConfig struct {
	MinCompressRange int
	MinSummaryLength int
	MaxSummaryLength int
}

type Config struct {
	ModelContextLimit int

	Tiers    TierConfig
	Nudge    NudgeConfig
	Truncate TruncateConfig
	Compress CompressConfig

	ProtectedTools []string

	IsToolProtected func(toolName string) bool

	PreserveRecentMessages int
	PreserveRecentTokens   int

	MaxCompressAttempts int
}

func DefaultConfig(modelContextLimit int) Config {
	return Config{
		ModelContextLimit: modelContextLimit,
		Tiers: TierConfig{
			Enabled:      true,
			MaxTier:      3,
			Tier2Trigger: 5,
			Tier3Trigger: 10,
		},
		Nudge: NudgeConfig{
			MaxContextLimitPct:    0.75,
			MinContextLimitPct:    0.45,
			EmergencyThresholdPct: 0.95,
			GrowthRatio:           0.05,
			GrowthFloor:           50_000,
			GrowthCap:             50_000,
			MinGrowthFloor:        20_000,
			MinGrowthRatio:        0.45,
			Tier2GrowthMultiplier: 1.5,
		},
		Truncate: TruncateConfig{Threshold: 0.95},
		Compress: CompressConfig{
			MinCompressRange: 5_000,
			MinSummaryLength: 50,
			MaxSummaryLength: 20_000,
		},
		PreserveRecentMessages: 5,
		PreserveRecentTokens:   5_000,
		MaxCompressAttempts:    3,
	}
}

func ValidateConfig(c Config) []string {
	var w []string
	add := func(format string, args ...any) { w = append(w, fmt.Sprintf(format, args...)) }

	if c.ModelContextLimit <= 0 {
		add("ModelContextLimit must be positive, got %d", c.ModelContextLimit)
	}
	if c.Nudge.MinContextLimitPct > c.Nudge.MaxContextLimitPct {
		add("Nudge.MinContextLimitPct (%g) must not exceed MaxContextLimitPct (%g)",
			c.Nudge.MinContextLimitPct, c.Nudge.MaxContextLimitPct)
	}
	if c.Nudge.MaxContextLimitPct > c.Nudge.EmergencyThresholdPct {
		add("Nudge.MaxContextLimitPct (%g) must not exceed EmergencyThresholdPct (%g)",
			c.Nudge.MaxContextLimitPct, c.Nudge.EmergencyThresholdPct)
	}
	if c.Truncate.Threshold <= 0 || c.Truncate.Threshold > 1 {
		add("Truncate.Threshold must be in (0, 1], got %g", c.Truncate.Threshold)
	}
	if c.Tiers.Tier2Trigger < 1 {
		add("Tiers.Tier2Trigger must be >= 1, got %d", c.Tiers.Tier2Trigger)
	}
	if c.Tiers.Tier3Trigger <= c.Tiers.Tier2Trigger {
		add("Tiers.Tier3Trigger (%d) must exceed Tier2Trigger (%d)",
			c.Tiers.Tier3Trigger, c.Tiers.Tier2Trigger)
	}
	if c.Tiers.MaxTier != 2 && c.Tiers.MaxTier != 3 {
		add("Tiers.MaxTier must be 2 or 3, got %d — the tier rule prompts only cover up to 3",
			c.Tiers.MaxTier)
	}
	if c.Compress.MinSummaryLength >= c.Compress.MaxSummaryLength {
		add("Compress.MinSummaryLength (%d) must be below MaxSummaryLength (%d)",
			c.Compress.MinSummaryLength, c.Compress.MaxSummaryLength)
	}
	if c.Nudge.MinPressureBenefitTokens != nil && *c.Nudge.MinPressureBenefitTokens < 0 {
		add("Nudge.MinPressureBenefitTokens must be >= 0, got %d", *c.Nudge.MinPressureBenefitTokens)
	}
	if c.MaxCompressAttempts < 1 {
		add("MaxCompressAttempts must be >= 1, got %d", c.MaxCompressAttempts)
	}
	return w
}

func (c Config) minPressureBenefit() int {
	if c.Nudge.MinPressureBenefitTokens != nil {
		return *c.Nudge.MinPressureBenefitTokens
	}
	return max(5000, roundHalfUp(float64(c.ModelContextLimit)*0.01))
}

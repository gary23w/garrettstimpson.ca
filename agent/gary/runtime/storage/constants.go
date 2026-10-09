package db

const (
	KindBegin   = "begin"
	KindGoal    = "goal"
	KindIntent  = "intent"
	KindFact    = "fact"
	KindFinding = "finding"
	KindHint    = "hint"
	KindDigest  = "digest"
)

const (
	StateDigestActive     = "active"
	StateDigestSuperseded = "superseded"
)

const StateOrigin = "origin"

const StateIntentDeleted = "deleted"

const (
	RelSpawns      = "spawns"
	RelDerivedFrom = "derived_from"
	RelYields      = "yields"
	RelProves      = "proves"
	RelCovers      = "covers"
)

package noa

import "math"

type TokenCountFn func(string) int

func DefaultCountTokens(text string) int {
	if text == "" {
		return 0
	}
	cjk, other := 0, 0
	for _, r := range text {
		if isCJK(r) {
			cjk++
		} else {
			other++
		}
	}
	return cjk + ceilDiv(other, 4)
}

func EstimateTokensFast(text string) int { return ceilDiv(len([]rune(text)), 4) }

func CountMessageTokens(m CoreMessage, count TokenCountFn) int {
	if count == nil {
		count = DefaultCountTokens
	}
	return count(m.Text)
}

func isCJK(r rune) bool {
	switch {
	case r >= 0x4E00 && r <= 0x9FFF:
		return true
	case r >= 0x3040 && r <= 0x30FF:
		return true
	case r >= 0xAC00 && r <= 0xD7AF:
		return true
	}
	return false
}

func ceilDiv(n, d int) int {
	if n <= 0 {
		return 0
	}
	return (n + d - 1) / d
}

func roundHalfUp(f float64) int { return int(math.Round(f)) }

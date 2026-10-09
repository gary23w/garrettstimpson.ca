package noaadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noa"
)

func DeriveMessageID(role noa.Role, ct noa.ContentType, text, toolCallID, toolName string) string {
	seed := string(role) + "|" + string(ct) + "|" + toolCallID + "|" + toolName + "|" + text
	sum := sha256.Sum256([]byte(seed))
	return "h_" + hex.EncodeToString(sum[:])[:16]
}

type ClusterCounter struct {
	counts map[string]int
}

func NewClusterCounter() *ClusterCounter {
	return &ClusterCounter{counts: map[string]int{}}
}

func (c *ClusterCounter) Next(base string) string {
	n := c.counts[base]
	c.counts[base] = n + 1
	if n == 0 {
		return base
	}
	return fmt.Sprintf("%s_%d", base, n)
}

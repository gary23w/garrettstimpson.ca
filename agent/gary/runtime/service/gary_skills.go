package server

import (
	"encoding/json"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/skill"
	"os"
	"path/filepath"
)

func loadGarySkills(dir string) (*skill.Registry, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	reg, err := skill.LoadDir(dir)
	if err != nil {
		return nil, err
	}
	file := os.Getenv("GARY_SKILL_REGISTRY")
	if file == "" {
		file = filepath.Join(dir, "registry.json")
	}
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return reg, nil
	}
	if err != nil {
		return nil, err
	}
	var catalog struct {
		Skills []struct {
			Name         string `json:"name"`
			Description  string `json:"description"`
			Instructions string `json:"instructions"`
			Directory    string `json:"directory"`
		} `json:"skills"`
	}
	if err = json.Unmarshal(data, &catalog); err != nil {
		return nil, err
	}
	for _, entry := range catalog.Skills {
		name := entry.Directory
		if name == "" {
			name = entry.Name
		}
		if _, ok := reg.Get(entry.Name); ok {
			continue
		}
		reg.Add(skill.Skill{Name: entry.Name, Description: entry.Description, Instructions: entry.Instructions, Dir: filepath.Join(filepath.Dir(file), name)})
	}
	return reg, nil
}

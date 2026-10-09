package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"
)

func TestGaryCatalogEnglishAndNativeSchemas(t *testing.T) {
	tools, err := GaryBuiltinCatalog("../../skills")
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 72 {
		t.Fatalf("got %d tools", len(tools))
	}
	b, _ := json.Marshal(tools)
	for _, r := range string(b) {
		if unicode.Is(unicode.Han, r) {
			t.Fatal("Non-English catalog string")
		}
	}
	found := map[string]bool{}
	for _, tool := range tools {
		found[tool.Name] = true
	}
	for _, name := range []string{"gary_bash", "gary_insert_assets", "gary_report_finding", "gary_traffic_get", "gary_spawn_task", "gary_skill", "gary_create_mcp", "gary_shell_open"} {
		if !found[name] {
			t.Fatal(name)
		}
	}
}

func TestGaryGatewayBoundary(t *testing.T) {
	const token = "gary-test-runtime-token-32-characters"
	gateway, err := NewGaryGateway(nil, token, "")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		method, path, body, auth, origin string
		status                           int
	}{
		{"POST", "/tools/run", "{}", "", "", 401},
		{"POST", "/tools/run", "{}", "Bearer " + token, "https://browser.example", 403},
		{"GET", "/tools/run", "", "Bearer " + token, "", 405},
		{"POST", "/wrong", "{}", "Bearer " + token, "", 404},
		{"POST", "/tools/run", "{", "Bearer " + token, "", 400},
		{"POST", "/tools/catalog", "{\"context\":{\"sessionId\":\"../bad\"}}", "Bearer " + token, "", 400},
	}
	for _, tc := range tests {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", tc.auth)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		gateway.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: got %d want %d", tc.path, w.Code, tc.status)
		}
	}
	if _, err = NewGaryGateway(nil, "short", ""); err == nil {
		t.Fatal("short secret accepted")
	}
}

func TestGaryTargetParserSkipsFilePaths(t *testing.T) {
	for _, input := range []string{"Read /app/data/fixture.txt", "Read C:\\fixtures\\report.md"} {
		if _, host, _, ok := parseTarget(input); ok { t.Fatalf("file path became a target: %s", host) }
	}
	scheme, host, port, ok := parseTarget("Read /app/data/fixture.txt then inspect example.com:8443")
	if !ok || scheme != "https" || host != "example.com" || port != 8443 { t.Fatalf("explicit target lost: %s %s %d %v", scheme, host, port, ok) }
}

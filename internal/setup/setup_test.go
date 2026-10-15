package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// setHome redirects the per-user directory that os.UserHomeDir resolves on
// every platform: HOME covers POSIX, USERPROFILE covers Windows.
func setHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func baseOpts(t *testing.T, agent string, scope Scope, projectDir string) Options {
	t.Helper()
	// Absolute POSIX-shaped inputs, matching how callers pass installed paths.
	// filepath.Abs normalizes them per-platform (a no-op on POSIX, a drive
	// prefix on Windows), so assertions use the normalized forms below.
	ashPath := "/usr/local/bin/ash"
	configPath := "/home/user/.config/ash/config.toml"
	if abs, err := filepath.Abs(ashPath); err == nil {
		ashPath = abs
	}
	if abs, err := filepath.Abs(configPath); err == nil {
		configPath = abs
	}
	return Options{
		Agent:      agent,
		Scope:      scope,
		ProjectDir: projectDir,
		AshPath:    ashPath,
		ConfigPath: configPath,
	}
}

func TestCodexSetupPreservesUnrelatedAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("CODEX_HOME", "")
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	original := "model = \"gpt-5\"\n\n[mcp_servers.other]\ncommand = \"other\"\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := baseOpts(t, "codex", UserScope, "")
	result, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Written || result.Path != path {
		t.Fatalf("%+v", result)
	}
	content := result.Content
	for _, want := range []string{`model = "gpt-5"`, "[mcp_servers.other]", "[mcp_servers.ash]", opts.AshPath, "--config", opts.ConfigPath, "mcp"} {
		if !strings.Contains(content, want) {
			t.Fatalf("missing %q in:\n%s", want, content)
		}
	}
	if strings.Count(content, "[mcp_servers.ash]") != 1 {
		t.Fatalf("duplicate ASH entry:\n%s", content)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil || string(onDisk) != content {
		t.Fatalf("on-disk mismatch: %v", err)
	}
	second, err := Run(baseOpts(t, "codex", UserScope, ""))
	if err != nil {
		t.Fatal(err)
	}
	if second.Written || second.Content != content {
		t.Fatalf("setup was not idempotent: %+v", second)
	}
}

func TestCodexSetupUpdatesExistingEntry(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("CODEX_HOME", "")
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	original := "[mcp_servers.ash]\ncommand = \"old\"\nargs = []\n\n[other]\nx = 1\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Run(baseOpts(t, "codex", UserScope, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Written || strings.Contains(result.Content, `"old"`) || !strings.Contains(result.Content, "[other]\nx = 1") {
		t.Fatalf("bad update:\n%s", result.Content)
	}
	if strings.Count(result.Content, "[mcp_servers.ash]") != 1 {
		t.Fatalf("duplicate ASH entry:\n%s", result.Content)
	}
}

// Updating the ASH table replaces only command and args; keys and comments the
// user added to that table, such as Codex approval settings, survive.
func TestCodexSetupKeepsOtherKeysInAshTable(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("CODEX_HOME", "")
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	original := "[mcp_servers.ash]\n" +
		"command = \"old\"\n" +
		"args = [\n  \"mcp\",\n]\n" +
		"# approve every tool\n" +
		"default_tools_approval_mode = \"approve\"\n\n" +
		"[mcp_servers.ash.tools.ash_exec]\n" +
		"approval_mode = \"approve\"\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := baseOpts(t, "codex", UserScope, "")
	result, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		MCPServers map[string]map[string]any `toml:"mcp_servers"`
	}
	if err := toml.Unmarshal([]byte(result.Content), &doc); err != nil {
		t.Fatalf("%v in:\n%s", err, result.Content)
	}
	ash := doc.MCPServers["ash"]
	if ash["command"] != opts.AshPath || ash["default_tools_approval_mode"] != "approve" {
		t.Fatalf("bad ASH table %v in:\n%s", ash, result.Content)
	}
	if args, _ := ash["args"].([]any); len(args) != 3 || args[2] != "mcp" {
		t.Fatalf("bad args %v in:\n%s", ash["args"], result.Content)
	}
	for _, want := range []string{"# approve every tool", "[mcp_servers.ash.tools.ash_exec]\napproval_mode = \"approve\""} {
		if !strings.Contains(result.Content, want) {
			t.Fatalf("missing %q in:\n%s", want, result.Content)
		}
	}
	second, err := Run(baseOpts(t, "codex", UserScope, ""))
	if err != nil || second.Written || second.Content != result.Content {
		t.Fatalf("not idempotent: %+v %v", second, err)
	}
}

func TestOpenCodeSetupKeepsOtherKeysInAshEntry(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	path := filepath.Join(home, ".config", "opencode", "opencode.json")
	original := `{"mcp":{"ash":{"type":"local","command":["old"],"timeout":5000,"environment":{"A":"1"}}}}`
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := baseOpts(t, "opencode", UserScope, "")
	result, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		MCP map[string]map[string]any `json:"mcp"`
	}
	if err := json.Unmarshal([]byte(result.Content), &doc); err != nil {
		t.Fatal(err)
	}
	ash := doc.MCP["ash"]
	command, _ := ash["command"].([]any)
	if len(command) == 0 || command[0] != opts.AshPath || ash["timeout"] != float64(5000) || ash["environment"] == nil {
		t.Fatalf("bad ASH entry in:\n%s", result.Content)
	}
}

func TestOpenCodeSetupPreservesOtherKeys(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	path := filepath.Join(home, ".config", "opencode", "opencode.json")
	original := `{"theme":"dark","mcp":{"existing":{"type":"local","command":["x"]}}}`
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := baseOpts(t, "opencode", UserScope, "")
	result, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	// JSON escapes path separators, so compare against the marshaled form.
	ashJSON, err := json.Marshal(opts.AshPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"theme": "dark"`, `"existing"`, `"ash"`, `"type": "local"`, `"enabled": true`, `https://opencode.ai/config.json`, string(ashJSON)} {
		if !strings.Contains(result.Content, want) {
			t.Fatalf("missing %q in:\n%s", want, result.Content)
		}
	}
	second, err := Run(baseOpts(t, "opencode", UserScope, ""))
	if err != nil || second.Written || second.Content != result.Content {
		t.Fatalf("not idempotent: %+v %v", second, err)
	}
}

func TestFreebuffProjectSetupAndScopeRestriction(t *testing.T) {
	project := t.TempDir()
	path := filepath.Join(project, ".agents", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	original := `{"mcpServers":{"other":{"command":"x","args":[]}}}`
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Run(baseOpts(t, "freebuff", ProjectScope, project))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Content, `"other"`) || !strings.Contains(result.Content, `"mcpServers"`) || !strings.Contains(result.Content, `"ash"`) {
		t.Fatalf("bad content:\n%s", result.Content)
	}
	if _, err := Run(baseOpts(t, "freebuff", UserScope, project)); err == nil {
		t.Fatal("accepted unsupported freebuff user scope")
	}
}

func TestPrintModeDoesNotWrite(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("CODEX_HOME", "")
	opts := baseOpts(t, "codex", UserScope, "")
	opts.Print = true
	result, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Written || result.Content == "" {
		t.Fatalf("%+v", result)
	}
	if _, err := os.Stat(result.Path); !os.IsNotExist(err) {
		t.Fatalf("print mode wrote a file: %v", err)
	}
}

func TestUnsupportedAgentAndManualExample(t *testing.T) {
	_, err := Run(baseOpts(t, "claude", UserScope, ""))
	if err == nil || !strings.Contains(err.Error(), "Manual configuration example") || !strings.Contains(err.Error(), "mcpServers") {
		t.Fatalf("%v", err)
	}
}

func TestCodexQuotedHeaderIsReplacedNotDuplicated(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("CODEX_HOME", "")
	path := filepath.Join(home, ".codex", "config.toml")
	// The quoted key spelling is the same TOML table as [mcp_servers.ash].
	original := "[mcp_servers.\"ash\"]\ncommand = \"old\"\n\n[other]\nx = 1\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := baseOpts(t, "codex", UserScope, "")
	result, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Written {
		t.Fatalf("expected write: %+v", result)
	}
	if strings.Count(result.Content, "mcp_servers") > 2 {
		t.Fatalf("duplicate ASH definitions:\n%s", result.Content)
	}
	if strings.Contains(result.Content, `"old"`) {
		t.Fatalf("stale command kept:\n%s", result.Content)
	}
	if !strings.Contains(result.Content, opts.AshPath) || !strings.Contains(result.Content, "[other]") {
		t.Fatalf("missing expected content:\n%s", result.Content)
	}
	// The result must parse as valid TOML with exactly one ash entry.
	content, _ := os.ReadFile(path)
	var doc struct {
		MCPServers map[string]any `toml:"mcp_servers"`
	}
	if err := toml.Unmarshal(content, &doc); err != nil {
		t.Fatalf("output is not valid TOML: %v\n%s", err, content)
	}
	if len(doc.MCPServers) != 1 {
		t.Fatalf("expected exactly one mcp_servers entry, got %d:\n%s", len(doc.MCPServers), content)
	}
}

// Every valid spelling of the ASH table header must be rewritten in place:
// only the ASH table's lines change, all comments (before, inside, and after
// unrelated sections) survive, and re-running setup is byte-for-byte
// idempotent.
func TestCodexQuotedSpellingsUpdatedInPlace(t *testing.T) {
	spellings := []string{
		`[mcp_servers.ash]`,
		`[mcp_servers."ash"]`,
		`["mcp_servers".ash]`,
		`["mcp_servers"."ash"]`,
	}
	for _, spelling := range spellings {
		t.Run(spelling, func(t *testing.T) {
			home := t.TempDir()
			setHome(t, home)
			t.Setenv("CODEX_HOME", "")
			path := filepath.Join(home, ".codex", "config.toml")
			original := "# leading comment about the model\n" +
				`model = "gpt-5"` + "\n\n" +
				"# server definitions follow\n" +
				"[mcp_servers.other]\n" +
				"# other's command, unrelated to ash\n" +
				`command = "other"` + "\n\n" +
				"# ash section lives between others\n" +
				spelling + "\n" +
				`command = "old"` + "\n" +
				"args = []\n\n" +
				"# profile section after the servers\n" +
				"[profile]\n" +
				"# trailing comment inside profile\n" +
				`style = "fast"` + "\n" +
				"# trailing comment at end of file\n"
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}
			result, err := Run(baseOpts(t, "codex", UserScope, ""))
			if err != nil {
				t.Fatal(err)
			}
			if !result.Written {
				t.Fatalf("expected a write for %s: %+v", spelling, result)
			}
			content := result.Content
			if strings.Contains(content, `"old"`) {
				t.Fatalf("stale command kept for %s:\n%s", spelling, content)
			}
			if !strings.Contains(content, optsCommand(t)) {
				t.Fatalf("new command missing for %s:\n%s", spelling, content)
			}
			// Exactly one ASH table, under the canonical spelling.
			if strings.Count(content, "[mcp_servers.ash]") != 1 {
				t.Fatalf("expected exactly one canonical ASH header for %s:\n%s", spelling, content)
			}
			if strings.Contains(content, spelling) && spelling != "[mcp_servers.ash]" {
				t.Fatalf("old spelling survived for %s:\n%s", spelling, content)
			}
			// Every comment line must survive untouched.
			for _, line := range strings.Split(original, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") && !strings.Contains(content, line) {
					t.Fatalf("comment lost for %s: %q\noutput:\n%s", spelling, line, content)
				}
			}
			// Unrelated values keep their exact bytes.
			for _, want := range []string{`model = "gpt-5"`, `command = "other"`, `style = "fast"`} {
				if !strings.Contains(content, want) {
					t.Fatalf("unrelated entry changed for %s, missing %q:\n%s", spelling, want, content)
				}
			}
			// Still valid TOML with exactly one ash entry.
			var doc struct {
				MCPServers map[string]any `toml:"mcp_servers"`
			}
			if err := toml.Unmarshal([]byte(content), &doc); err != nil {
				t.Fatalf("output is not valid TOML for %s: %v\n%s", spelling, err, content)
			}
			if _, ok := doc.MCPServers["ash"]; !ok {
				t.Fatalf("ash entry missing for %s:\n%s", spelling, content)
			}
			if len(doc.MCPServers) != 2 {
				t.Fatalf("unexpected mcp_servers entries for %s:\n%s", spelling, content)
			}
			if _, ok := doc.MCPServers["other"]; !ok {
				t.Fatalf("unrelated server lost for %s:\n%s", spelling, content)
			}
			// Re-running setup must be byte-for-byte idempotent.
			second, err := Run(baseOpts(t, "codex", UserScope, ""))
			if err != nil {
				t.Fatal(err)
			}
			if second.Written || second.Content != content {
				t.Fatalf("setup not byte-for-byte idempotent for %s:\nfirst:\n%s\nsecond:\n%s", spelling, content, second.Content)
			}
		})
	}
}

// optsCommand renders the command line setup writes, mirroring Run's
// rendering of the configured ash path and config path.
func optsCommand(t *testing.T) string {
	t.Helper()
	opts := baseOpts(t, "codex", UserScope, "")
	return opts.AshPath
}

// A multi-line array and multi-line strings must not hide a table header from
// the in-place updater: the literal "[mcp_servers.ash]" appearing inside them
// is data, not a header.
func TestCodexHeaderInsideMultilineDataIsNotAMember(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("CODEX_HOME", "")
	path := filepath.Join(home, ".codex", "config.toml")
	original := "[other]\n" +
		"text = \"\"\"\n" +
		"[mcp_servers.ash]\n" +
		"\"\"\"\n" +
		"array = [\n" +
		"\t\"[mcp_servers.ash]\",\n" +
		"]\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Run(baseOpts(t, "codex", UserScope, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Written {
		t.Fatal("expected a write")
	}
	// ASH did not exist as a table; setup must append it, not rewrite other.
	// The literal header also appears inside the multi-line string and the
	// array element, where it is data, so assert on parsed semantics.
	var doc struct {
		MCPServers map[string]any `toml:"mcp_servers"`
		Other      map[string]any `toml:"other"`
	}
	if err := toml.Unmarshal([]byte(result.Content), &doc); err != nil {
		t.Fatalf("output is not valid TOML: %v\n%s", err, result.Content)
	}
	if _, ok := doc.MCPServers["ash"]; !ok || len(doc.MCPServers) != 1 {
		t.Fatalf("expected exactly the appended ash server: %+v\n%s", doc.MCPServers, result.Content)
	}
	text, _ := doc.Other["text"].(string)
	if !strings.Contains(text, "[mcp_servers.ash]") {
		t.Fatalf("multi-line string data damaged: %q\n%s", text, result.Content)
	}
	array, _ := doc.Other["array"].([]any)
	if len(array) != 1 || array[0] != "[mcp_servers.ash]" {
		t.Fatalf("array data damaged: %+v\n%s", array, result.Content)
	}
}

// Invalid TOML must be reported, never overwritten.
func TestCodexInvalidTOMLIsRejected(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("CODEX_HOME", "")
	path := filepath.Join(home, ".codex", "config.toml")
	broken := "[mcp_servers.ash\ncommand = \"unterminated\"\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Run(baseOpts(t, "codex", UserScope, ""))
	if err == nil {
		t.Fatalf("invalid TOML accepted: %+v", result)
	}
	if !strings.Contains(err.Error(), "parse existing config") {
		t.Fatalf("unexpected error: %v", err)
	}
	onDisk, readErr := os.ReadFile(path)
	if readErr != nil || string(onDisk) != broken {
		t.Fatalf("invalid config was overwritten: %v\n%s", readErr, onDisk)
	}
}

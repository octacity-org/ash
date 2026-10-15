// Package setup registers ASH as a stdio MCP server with supported coding agents.
//
// It writes only the target agent's documented MCP configuration file, preserves
// unrelated entries, and is idempotent: re-running setup never creates a
// duplicate ASH entry.
package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type Scope string

const (
	UserScope    Scope = "user"
	ProjectScope Scope = "project"
)

// Adapter describes one supported coding agent and where it stores MCP servers.
type Adapter struct {
	Name string
	// Scopes lists the configuration scopes the agent supports.
	Scopes []Scope
	// Path resolves the configuration file for a scope.
	Path func(scope Scope, projectDir string) (string, error)
	// Render produces the full configuration file from its current contents.
	Render func(existing []byte, command []string) ([]byte, error)
	// Restart tells the user how to pick up the change.
	Restart string
}

// Options controls one setup invocation.
type Options struct {
	Agent      string
	Scope      Scope
	ProjectDir string
	AshPath    string
	ConfigPath string
	Print      bool
}

// Result reports what setup did and the exact configuration it produced.
type Result struct {
	Agent   string   `json:"agent"`
	Scope   Scope    `json:"scope"`
	Path    string   `json:"path"`
	Command []string `json:"command"`
	Written bool     `json:"written"`
	Content string   `json:"content"`
	Restart string   `json:"restart"`
}

func adapters() []Adapter {
	return []Adapter{
		{
			Name:    "codex",
			Scopes:  []Scope{UserScope, ProjectScope},
			Path:    codexPath,
			Render:  renderCodex,
			Restart: "Restart Codex (or start a new session) so it reloads config.toml.",
		},
		{
			Name:    "opencode",
			Scopes:  []Scope{UserScope, ProjectScope},
			Path:    opencodePath,
			Render:  renderOpenCode,
			Restart: "Restart OpenCode so it reloads its config and starts the ASH MCP server.",
		},
		{
			Name:   "freebuff",
			Scopes: []Scope{ProjectScope},
			Path:   freebuffPath,
			Render: renderFreebuff,
			Restart: "Restart freebuff from the project directory so it reloads .agents/mcp.json. " +
				"Freebuff trust-gates project MCP files: on first use it asks you to approve " +
				"this directory's .agents/mcp.json; accept that prompt to enable the ASH tools.",
		},
	}
}

// Agents returns the supported adapters sorted by name.
func Agents() []Adapter {
	out := adapters()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns the adapter for an agent name.
func Lookup(name string) (Adapter, bool) {
	for _, a := range adapters() {
		if a.Name == name {
			return a, true
		}
	}
	return Adapter{}, false
}

// ManualExample returns the generic stdio configuration for unsupported agents.
func ManualExample(command []string) string {
	entry := map[string]any{"mcpServers": map[string]any{"ash": map[string]any{
		"command": command[0],
		"args":    command[1:],
	}}}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return ""
	}
	return string(data) + "\n"
}

// Run renders (and unless Print is set, writes) the ASH MCP entry for one agent.
func Run(opts Options) (Result, error) {
	adapter, ok := Lookup(opts.Agent)
	if !ok {
		names := make([]string, 0)
		for _, a := range Agents() {
			names = append(names, a.Name)
		}
		cmd, err := command(nil, opts)
		if err != nil {
			return Result{}, err
		}
		return Result{}, fmt.Errorf("unsupported agent %q; supported: %s\n\nManual configuration example:\n%s", opts.Agent, strings.Join(names, ", "), ManualExample(cmd))
	}
	scope := opts.Scope
	if scope == "" {
		if len(adapter.Scopes) > 0 {
			scope = adapter.Scopes[0]
		}
	}
	if !supports(adapter.Scopes, scope) {
		return Result{}, fmt.Errorf("%s does not support %s scope; supported scopes: %s", adapter.Name, scope, scopeList(adapter.Scopes))
	}
	projectDir := opts.ProjectDir
	if projectDir == "" {
		dir, err := os.Getwd()
		if err != nil {
			return Result{}, err
		}
		projectDir = dir
	}
	cmd, err := command(&adapter, opts)
	if err != nil {
		return Result{}, err
	}
	path, err := adapter.Path(scope, projectDir)
	if err != nil {
		return Result{}, err
	}
	existing, readErr := os.ReadFile(path)
	if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
		return Result{}, fmt.Errorf("read %s: %w", path, readErr)
	}
	content, err := adapter.Render(existing, cmd)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", adapter.Name, err)
	}
	result := Result{Agent: adapter.Name, Scope: scope, Path: path, Command: cmd, Content: string(content), Restart: adapter.Restart}
	if opts.Print {
		return result, nil
	}
	if errors.Is(readErr, fs.ErrNotExist) || !bytes.Equal(existing, content) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return Result{}, fmt.Errorf("create %s: %w", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			return Result{}, fmt.Errorf("write %s: %w", path, err)
		}
		result.Written = true
	}
	return result, nil
}

func command(adapter *Adapter, opts Options) ([]string, error) {
	ashPath := opts.AshPath
	if ashPath == "" {
		var err error
		ashPath, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("resolve ASH executable: %w", err)
		}
	}
	ashPath, err := filepath.Abs(ashPath)
	if err != nil {
		return nil, fmt.Errorf("resolve ASH executable: %w", err)
	}
	configPath := opts.ConfigPath
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		configPath = filepath.Join(home, ".config", "ash", "config.toml")
	}
	return []string{ashPath, "--config", configPath, "mcp"}, nil
}

func supports(scopes []Scope, scope Scope) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func scopeList(scopes []Scope) string {
	names := make([]string, 0, len(scopes))
	for _, s := range scopes {
		names = append(names, string(s))
	}
	return strings.Join(names, ", ")
}

func codexPath(scope Scope, projectDir string) (string, error) {
	if scope == ProjectScope {
		return filepath.Join(projectDir, ".codex", "config.toml"), nil
	}
	if home := os.Getenv("CODEX_HOME"); home != "" {
		return filepath.Join(home, "config.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".codex", "config.toml"), nil
}

func opencodePath(scope Scope, projectDir string) (string, error) {
	if scope == ProjectScope {
		return filepath.Join(projectDir, "opencode.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "opencode", "opencode.json"), nil
}

func freebuffPath(scope Scope, projectDir string) (string, error) {
	if scope != ProjectScope {
		return "", fmt.Errorf("freebuff only documents project-level setup; use --scope project")
	}
	return filepath.Join(projectDir, ".agents", "mcp.json"), nil
}

func renderCodex(existing []byte, command []string) ([]byte, error) {
	block, err := toml.Marshal(struct {
		Command string   `toml:"command"`
		Args    []string `toml:"args"`
	}{Command: command[0], Args: command[1:]})
	if err != nil {
		return nil, err
	}
	header := "[mcp_servers.ash]"
	section := header + "\n" + string(block)
	// An existing ASH table can be spelled with quoted keys, e.g.
	// [mcp_servers."ash"], which is the same TOML table. Detect membership
	// semantically first so the textual upsert replaces instead of appending
	// a duplicate definition.
	present, err := tomlHasAshServer(existing)
	if err != nil {
		return nil, err
	}
	result, err := upsertTOMLSection(string(existing), header, section, present)
	if err != nil {
		return nil, err
	}
	return []byte(result), nil
}

// tomlHasAshServer reports whether the document already defines
// mcp_servers.ash under any valid key spelling, and whether the document
// parses at all.
func tomlHasAshServer(existing []byte) (bool, error) {
	trimmed := strings.TrimSpace(string(existing))
	if trimmed == "" {
		return false, nil
	}
	var doc struct {
		MCPServers map[string]any `toml:"mcp_servers"`
	}
	if err := toml.Unmarshal(existing, &doc); err != nil {
		return false, fmt.Errorf("parse existing config: %w", err)
	}
	_, ok := doc.MCPServers["ash"]
	return ok, nil
}

// upsertTOMLSection replaces the existing ASH table header - whatever valid
// spelling it uses - and the keys the canonical section sets, or appends the
// section. Other keys and comments in that table, and every byte outside it,
// survive untouched.
func upsertTOMLSection(doc, header, section string, present bool) (string, error) {
	doc = strings.TrimRight(doc, "\n")
	lines := strings.Split(doc, "\n")
	sectionLines := strings.Split(strings.TrimRight(section, "\n"), "\n")
	key, _, ok := parseTableHeader(header)
	if !ok {
		return "", fmt.Errorf("internal: unsupported canonical header %q", header)
	}
	start, end := findTOMLTable(lines, key...)
	if start != -1 {
		owned := map[string]bool{}
		for _, line := range sectionLines[1:] {
			if k, ok := assignmentKey(line); ok {
				owned[strings.Join(k, ".")] = true
			}
		}
		kept := withoutKeys(lines[start+1:end], owned)
		out := make([]string, 0, start+len(sectionLines)+len(kept)+len(lines)-end)
		out = append(out, lines[:start]...)
		out = append(out, sectionLines...)
		out = append(out, kept...)
		out = append(out, lines[end:]...)
		return strings.Join(out, "\n") + "\n", nil
	}
	if present {
		// Semantically present but not a splicable table: dotted keys, an
		// inline table, or an array of tables. Rewriting those in place would
		// mean re-marshalling the document; refuse instead.
		return "", fmt.Errorf("mcp_servers.ash exists in a form that cannot be updated in place (dotted keys, inline table, or array of tables); rewrite it as a [mcp_servers.\"ash\"] table and retry")
	}
	var out []string
	if strings.TrimSpace(doc) != "" {
		out = append(out, lines...)
		out = append(out, "")
	}
	out = append(out, sectionLines...)
	return strings.Join(out, "\n") + "\n", nil
}

// withoutKeys drops the key/value lines of a table body whose dotted key is
// owned, including continuation lines of multi-line arrays and strings.
func withoutKeys(body []string, owned map[string]bool) []string {
	state := &tomlLineState{}
	kept := make([]string, 0, len(body))
	skipping := false
	for _, line := range body {
		if state.depth == 0 && state.multiline == 0 {
			key, ok := assignmentKey(line)
			skipping = ok && owned[strings.Join(key, ".")]
		}
		state.consume(line)
		if !skipping {
			kept = append(kept, line)
		}
	}
	return kept
}

// assignmentKey parses the dotted key of a `key = value` line.
func assignmentKey(line string) ([]string, bool) {
	s := strings.TrimLeft(line, " \t")
	var parts []string
	for {
		part, rest, err := parseTOMLKeyPart(s)
		if err != nil {
			return nil, false
		}
		parts = append(parts, part)
		s = strings.TrimLeft(rest, " \t")
		if !strings.HasPrefix(s, ".") {
			break
		}
		s = strings.TrimLeft(s[1:], " \t")
	}
	return parts, strings.HasPrefix(s, "=")
}

// findTOMLTable locates the [start, end) line range of the single table
// definition whose dotted key equals want. Lines inside multi-line strings or
// still-open arrays are never treated as table headers.
func findTOMLTable(lines []string, want ...string) (int, int) {
	state := &tomlLineState{}
	for i, line := range lines {
		key, header, single := state.scan(line)
		if !header {
			continue
		}
		if equalKey(key, want) && single {
			return i, tableEnd(lines, i)
		}
	}
	return -1, -1
}

// tableEnd returns the exclusive end line of the table starting at start: the
// next top-level table header, or the end of the document. Blank and
// comment-only lines directly before the next header belong to neither table
// and stay outside the replaced range.
func tableEnd(lines []string, start int) int {
	state := &tomlLineState{}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if _, header, _ := state.scan(lines[i]); header {
			end = i
			break
		}
	}
	for end > start+1 && isBlankOrComment(lines[end-1]) {
		end--
	}
	return end
}

func isBlankOrComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

func equalKey(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// tomlLineState tracks what a line-oriented view of TOML cannot see on its
// own: whether a multi-line string or an unclosed array is still open.
type tomlLineState struct {
	depth     int
	multiline int // 0 none, 1 basic """ string, 2 literal ''' string
}

// scan processes one line. When the line opens a new table at top level it
// reports the parsed dotted key, whether it is a table header, and whether it
// is a single table (false means an array-of-tables header).
func (s *tomlLineState) scan(line string) (key []string, header bool, single bool) {
	if s.depth == 0 && s.multiline == 0 {
		if key, aot, ok := parseTableHeader(line); ok {
			return key, true, !aot
		}
	}
	s.consume(line)
	return nil, false, false
}

// consume feeds one non-header line into the open-construct state.
func (s *tomlLineState) consume(line string) {
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case s.multiline == 1:
			if c == '\\' {
				i++
			} else if strings.HasPrefix(line[i:], `"""`) {
				s.multiline = 0
				i += 2
			}
		case s.multiline == 2:
			if strings.HasPrefix(line[i:], `'''`) {
				s.multiline = 0
				i += 2
			}
		case c == '#':
			return // comment runs to the end of the line
		case c == '"':
			if strings.HasPrefix(line[i:], `"""`) {
				s.multiline = 1
				i += 2
				continue
			}
			i++
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' {
					i++
				}
				i++
			}
		case c == '\'':
			if strings.HasPrefix(line[i:], `'''`) {
				s.multiline = 2
				i += 2
				continue
			}
			i++
			for i < len(line) && line[i] != '\'' {
				i++
			}
		case c == '[':
			s.depth++
		case c == ']':
			if s.depth > 0 {
				s.depth--
			}
		}
	}
}

// parseTableHeader parses a single-line table header, reporting its dotted
// key. It accepts bare, basic-string, and literal-string key parts, optional
// whitespace, and a trailing comment, so [mcp_servers.ash],
// [mcp_servers."ash"], ["mcp_servers".ash], and ["mcp_servers"."ash"] all
// resolve to the same table. Array-of-tables headers are reported as headers
// but flagged via aot.
func parseTableHeader(line string) (key []string, aot bool, ok bool) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "[") {
		return nil, false, false
	}
	if strings.HasPrefix(s, "[[") {
		s = s[2:]
		aot = true
	} else {
		s = s[1:]
	}
	var parts []string
	for {
		s = strings.TrimLeft(s, " \t")
		part, rest, err := parseTOMLKeyPart(s)
		if err != nil {
			return nil, false, false
		}
		parts = append(parts, part)
		s = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(s, ".") {
			s = s[1:]
			continue
		}
		break
	}
	closing := "]"
	if aot {
		closing = "]]"
	}
	if !strings.HasPrefix(s, closing) {
		return nil, false, false
	}
	s = strings.TrimLeft(s[len(closing):], " \t")
	if s != "" && !strings.HasPrefix(s, "#") {
		return nil, false, false
	}
	return parts, aot, true
}

// parseTOMLKeyPart parses one key part: bare, basic string, or literal string.
func parseTOMLKeyPart(s string) (part, rest string, err error) {
	switch {
	case strings.HasPrefix(s, `"`):
		i := 1
		for i < len(s) {
			if s[i] == '\\' {
				i += 2
				continue
			}
			if s[i] == '"' {
				break
			}
			i++
		}
		if i >= len(s) {
			return "", "", fmt.Errorf("unterminated basic-string key")
		}
		unquoted, uerr := strconv.Unquote(s[:i+1])
		if uerr != nil {
			return "", "", uerr
		}
		return unquoted, s[i+1:], nil
	case strings.HasPrefix(s, `'`):
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			return "", "", fmt.Errorf("unterminated literal-string key")
		}
		return s[1 : 1+end], s[2+end:], nil
	default:
		i := 0
		for i < len(s) && isBareKeyChar(s[i]) {
			i++
		}
		if i == 0 {
			return "", "", fmt.Errorf("not a key part")
		}
		return s[:i], s[i:], nil
	}
}

func isBareKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func renderOpenCode(existing []byte, command []string) ([]byte, error) {
	entry := map[string]any{"type": "local", "command": command, "enabled": true}
	return upsertJSONEntry(existing, "mcp", "ash", entry, "https://opencode.ai/config.json")
}

func renderFreebuff(existing []byte, command []string) ([]byte, error) {
	entry := map[string]any{"command": command[0], "args": command[1:]}
	return upsertJSONEntry(existing, "mcpServers", "ash", entry, "")
}

// upsertJSONEntry sets entry's keys on root[container][name] while preserving
// every other key, including other keys of an existing entry. Invalid JSON is
// reported rather than overwritten.
func upsertJSONEntry(existing []byte, container, name string, entry map[string]any, schema string) ([]byte, error) {
	root := map[string]any{}
	if trimmed := strings.TrimSpace(string(existing)); trimmed != "" {
		if err := json.Unmarshal(existing, &root); err != nil {
			return nil, fmt.Errorf("parse existing config: %w", err)
		}
	}
	servers, _ := root[container].(map[string]any)
	if raw, ok := root[container]; ok && raw != nil && servers == nil {
		return nil, fmt.Errorf("existing %q is not an object", container)
	}
	if servers == nil {
		servers = map[string]any{}
	}
	if current, ok := servers[name].(map[string]any); ok {
		for k, v := range entry {
			current[k] = v
		}
		entry = current
	}
	servers[name] = entry
	root[container] = servers
	if schema != "" {
		if _, ok := root["$schema"]; !ok {
			root["$schema"] = schema
		}
	}
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

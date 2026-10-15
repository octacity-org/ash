package doctor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ash/internal/host"
	"ash/internal/policy"
	"ash/internal/transport"
)

type fakeTransport struct {
	transport.Transport
	err      error
	results  map[string]transport.ExecResult
	commands []string
}

func (f *fakeTransport) Exec(_ context.Context, _ host.Host, req transport.ExecRequest) (transport.ExecResult, error) {
	f.commands = append(f.commands, req.Command)
	if f.err != nil {
		return transport.ExecResult{}, f.err
	}
	if r, ok := f.results[req.Command]; ok {
		return r, nil
	}
	return transport.ExecResult{}, nil
}

func testDoctor(t *testing.T, f *fakeTransport, pol policy.Policy) *Doctor {
	t.Helper()
	known := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(known, []byte("host ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(host.New(map[string]host.Host{"h": {Address: "example", Port: 22, User: "u", Policy: pol}}), f, known)
}

func find(checks []Check) (Check, bool) {
	for _, check := range checks {
		if check.Name == "trust" || check.Name == "auth" || check.Name == "network" || check.Name == "shell" || check.Name == "cache" || check.Name == "zellij" {
			return check, true
		}
	}
	return Check{}, false
}

// findCheck returns the check with exactly the given name.
func findCheck(checks []Check, name string) (Check, bool) {
	for _, check := range checks {
		if check.Name == name {
			return check, true
		}
	}
	return Check{}, false
}

func TestRemoteSuccess(t *testing.T) {
	f := &fakeTransport{results: map[string]transport.ExecResult{
		`command -v zellij >/dev/null 2>&1 && zellij --version`: {Stdout: "zellij 0.44.0\n"},
	}}
	d := testDoctor(t, f, policy.Policy{Exec: true})
	report := d.Run(context.Background(), "h")
	if report.Failed() {
		t.Fatalf("unexpected failure: %+v", report)
	}
	names := map[string]Status{}
	for _, check := range report.Checks {
		names[check.Name] = check.Status
	}
	for _, name := range []string{"config", "known_hosts", "host", "policy", "trust", "auth", "shell", "cache", "zellij"} {
		if names[name] != StatusOK {
			t.Fatalf("check %s = %s (%+v)", name, names[name], report.Checks)
		}
	}
}

func TestMissingZellijIsWarningNotFailure(t *testing.T) {
	f := &fakeTransport{results: map[string]transport.ExecResult{
		`command -v zellij >/dev/null 2>&1 && zellij --version`: {ExitCode: 1},
	}}
	report := testDoctor(t, f, policy.Policy{Exec: true}).Run(context.Background(), "h")
	if report.Failed() {
		t.Fatalf("missing zellij should warn: %+v", report.Checks)
	}
	for _, check := range report.Checks {
		if check.Name == "zellij" && check.Status != StatusWarn {
			t.Fatalf("zellij = %s", check.Status)
		}
	}
}

func TestTrustAndAuthFailuresAreDistinguished(t *testing.T) {
	trust := testDoctor(t, &fakeTransport{err: fmt.Errorf("%w: not trusted", transport.ErrHostKey)}, policy.Policy{Exec: true})
	report := trust.Run(context.Background(), "h")
	if !report.Failed() {
		t.Fatal("expected failure")
	}
	check, ok := find(report.Checks)
	if !ok || check.Name != "trust" || check.Status != StatusFail {
		t.Fatalf("%+v", report.Checks)
	}
	auth := testDoctor(t, &fakeTransport{err: fmt.Errorf("%w: bad key", transport.ErrAuthentication)}, policy.Policy{Exec: true})
	report = auth.Run(context.Background(), "h")
	check, ok = find(report.Checks)
	if !ok || check.Name != "auth" || check.Status != StatusFail {
		t.Fatalf("%+v", report.Checks)
	}
}

func TestRemoteChecksSkipWithoutExec(t *testing.T) {
	f := &fakeTransport{}
	report := testDoctor(t, f, policy.Policy{Read: true}).Run(context.Background(), "h")
	for _, check := range report.Checks {
		if check.Name == "shell" && check.Status != StatusSkip {
			t.Fatalf("shell = %s", check.Status)
		}
	}
	if len(f.commands) != 1 {
		t.Fatalf("expected only the connectivity probe, got %v", f.commands)
	}
}

func TestUnknownHostAndLocalChecks(t *testing.T) {
	f := &fakeTransport{}
	d := testDoctor(t, f, policy.Policy{Exec: true})
	report := d.Run(context.Background(), "missing")
	if !report.Failed() {
		t.Fatalf("expected failure: %+v", report.Checks)
	}
	if len(f.commands) != 0 {
		t.Fatalf("unknown host should not connect: %v", f.commands)
	}
	local := d.Local()
	if local.Failed() {
		t.Fatalf("local checks failed: %+v", local.Checks)
	}
	missing := New(host.New(nil), f, filepath.Join(t.TempDir(), "absent"))
	for _, check := range missing.Local().Checks {
		if check.Name == "known_hosts" && check.Status != StatusWarn {
			t.Fatalf("known_hosts = %s", check.Status)
		}
	}
}

func TestDiagnosticsDoNotEchoIdentityPaths(t *testing.T) {
	known := filepath.Join(t.TempDir(), "known_hosts")
	os.WriteFile(known, []byte("x\n"), 0o600)
	d := New(host.New(map[string]host.Host{"h": {Identity: "/secret/id_rsa", Policy: policy.Policy{Exec: true}}}), &fakeTransport{err: fmt.Errorf("%w: read identity /secret/id_rsa", transport.ErrAuthentication)}, known)
	report := d.Run(context.Background(), "h")
	for _, check := range report.Checks {
		if strings.Contains(check.Message+check.Hint, "/secret") {
			t.Fatalf("diagnostic leaked identity path: %+v", check)
		}
	}
	if report.Host != "h" {
		t.Fatalf("%+v", report)
	}
}

// Diagnostics must not mutate the host: no mkdir in any issued command.
func TestCacheCheckDoesNotMutate(t *testing.T) {
	f := &fakeTransport{}
	d := testDoctor(t, f, policy.Policy{Exec: true})
	report := d.Run(context.Background(), "h")
	_ = report
	for _, command := range f.commands {
		if strings.Contains(command, "mkdir") {
			t.Fatalf("doctor issued a mutating command: %q", command)
		}
	}
	// Missing cache directory with a writable parent yields a warning, not a
	// failure, and ASH would create it on first use.
	f2 := &fakeTransport{results: map[string]transport.ExecResult{
		cacheCheckCommand: {ExitCode: 3},
	}}
	d2 := testDoctor(t, f2, policy.Policy{Exec: true})
	report2 := d2.Run(context.Background(), "h")
	for _, check := range report2.Checks {
		if check.Name == "cache" {
			if check.Status != StatusWarn {
				t.Fatalf("missing cache dir should warn, got %+v", check)
			}
			return
		}
	}
	t.Fatal("cache check missing from report")
}

func TestCacheCheckStates(t *testing.T) {
	cases := map[string]struct {
		result      transport.ExecResult
		want        Status
		wantMessage string
	}{
		"existing writable cache":               {transport.ExecResult{ExitCode: 0}, StatusOK, "remote cache directory is writable"},
		"existing non-writable cache":           {transport.ExecResult{ExitCode: 1}, StatusFail, "remote cache directory is not writable"},
		"cache exists but is not a directory":   {transport.ExecResult{ExitCode: 2}, StatusFail, "$HOME/.cache/ash exists but is not a directory"},
		"missing cache with writable parent":    {transport.ExecResult{ExitCode: 3}, StatusWarn, "remote cache directory is missing; ASH will create it on first use"},
		"cache parent exists but is not a dir":  {transport.ExecResult{ExitCode: 4}, StatusFail, "$HOME/.cache exists but is not a directory"},
		"missing cache without writable parent": {transport.ExecResult{ExitCode: 5}, StatusFail, "remote cache directory is missing and $HOME/.cache is not writable"},
	}
	for name, tc := range cases {
		f := &fakeTransport{results: map[string]transport.ExecResult{cacheCheckCommand: tc.result}}
		report := testDoctor(t, f, policy.Policy{Exec: true}).Run(context.Background(), "h")
		got, ok := findCheck(report.Checks, "cache")
		if !ok {
			t.Fatalf("%s: cache check missing: %+v", name, report.Checks)
		}
		if got.Status != tc.want {
			t.Fatalf("%s: cache = %s, want %s (%+v)", name, got.Status, tc.want, got)
		}
		if got.Message != tc.wantMessage {
			t.Fatalf("%s: message = %q, want %q", name, got.Message, tc.wantMessage)
		}
	}
}

// The two non-directory states must be distinguishable: the message has to
// name the component that actually blocks the path, because the remedy
// differs (the blocking file may sit at ~/.cache itself rather than
// ~/.cache/ash).
func TestCacheCheckNonDirectoryMessages(t *testing.T) {
	cases := map[string]struct {
		exitCode int
		want     string
	}{
		"ash path is not a directory":   {2, "$HOME/.cache/ash exists but is not a directory"},
		"cache path is not a directory": {4, "$HOME/.cache exists but is not a directory"},
	}
	for name, tc := range cases {
		f := &fakeTransport{results: map[string]transport.ExecResult{
			cacheCheckCommand: {ExitCode: tc.exitCode},
		}}
		report := testDoctor(t, f, policy.Policy{Exec: true}).Run(context.Background(), "h")
		check, ok := findCheck(report.Checks, "cache")
		if !ok || check.Status != StatusFail {
			t.Fatalf("%s: expected failing cache check, got %+v", name, report.Checks)
		}
		if check.Message != tc.want {
			t.Fatalf("%s: message = %q, want %q", name, check.Message, tc.want)
		}
	}
}

// cacheProbeTransport succeeds for the connectivity probe and fails only for
// the cache command, isolating the transport failure handling inside
// cacheCheck.
type cacheProbeTransport struct {
	transport.Transport
	err error
}

func (c cacheProbeTransport) Exec(_ context.Context, _ host.Host, req transport.ExecRequest) (transport.ExecResult, error) {
	if req.Command == cacheCheckCommand {
		return transport.ExecResult{}, c.err
	}
	return transport.ExecResult{}, nil
}

// testDoctorWithTransport builds a Doctor around an arbitrary transport.
func testDoctorWithTransport(t *testing.T, tr transport.Transport, pol policy.Policy) *Doctor {
	t.Helper()
	known := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(known, []byte("host ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(host.New(map[string]host.Host{"h": {Address: "example", Port: 22, User: "u", Policy: pol}}), tr, known)
}

func TestCacheCheckTransportFailureClassified(t *testing.T) {
	// The regression: a transport error surfaced a zero-value result whose
	// ExitCode is 0, reporting a healthy cache. It must classify as a failure.
	for _, err := range []error{
		fmt.Errorf("%w: dial failed", transport.ErrTimeout),
		fmt.Errorf("connection reset by peer"),
	} {
		f := &cacheProbeTransport{err: err}
		report := testDoctorWithTransport(t, f, policy.Policy{Exec: true}).Run(context.Background(), "h")
		if !report.Failed() {
			t.Fatalf("transport failure must fail the report: %+v", report.Checks)
		}
		for _, check := range report.Checks {
			if check.Name == "cache" {
				if check.Status != StatusFail {
					t.Fatalf("transport failure reported as %s: %+v", check.Status, check)
				}
				if check.Status == StatusOK {
					t.Fatalf("transport failure reported as healthy cache: %+v", check)
				}
			}
		}
	}
}

// failureAfterProbeTransport succeeds for the connectivity probe, shell and
// zellij commands but fails the cache command, isolating the transport
// failure handling inside cacheCheck.
type failureAfterProbeTransport struct {
	transport.Transport
	err error
}

func (c *failureAfterProbeTransport) Exec(_ context.Context, _ host.Host, req transport.ExecRequest) (transport.ExecResult, error) {
	if req.Command == cacheCheckCommand {
		return transport.ExecResult{}, c.err
	}
	return transport.ExecResult{}, nil
}

func TestCacheCheckTransportFailurePropagates(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("%w: dial failed", transport.ErrTimeout),
		fmt.Errorf("connection reset by peer"),
	} {
		f := &failureAfterProbeTransport{err: err}
		report := testDoctorWithTransport(t, f, policy.Policy{Exec: true}).Run(context.Background(), "h")
		if !report.Failed() {
			t.Fatalf("transport failure during the cache check must fail the report: %+v", report.Checks)
		}
		found := false
		for _, check := range report.Checks {
			// The failure is classified like every other remote transport
			// error (network/timeout), so it is visible and distinguishable
			// from any cache state, including the healthy exit code.
			if check.Name == "network" && check.Status == StatusFail {
				found = true
			}
			// The failure must not claim the cache directory exists or is
			// fine (the old bug reported success with the zero exit code).
			if check.Name == "cache" && check.Status != StatusFail && check.Message != "" {
				t.Fatalf("transport failure reported as cache state %q: %+v", check.Status, check)
			}
		}
		if !found {
			t.Fatalf("transport failure was not classified: %+v", report.Checks)
		}
	}
}

func TestCacheCheckRunsSingleCommand(t *testing.T) {
	f := &fakeTransport{results: map[string]transport.ExecResult{
		cacheCheckCommand: {},
	}}
	testDoctor(t, f, policy.Policy{Exec: true}).Run(context.Background(), "h")
	count := 0
	for _, command := range f.commands {
		if command == cacheCheckCommand {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("cache state must come from one combined probe, got %d invocations", count)
	}
}

func TestTmuxHostChecksTmuxNotZellij(t *testing.T) {
	f := &fakeTransport{results: map[string]transport.ExecResult{
		`command -v tmux >/dev/null 2>&1 && tmux -V`: {Stdout: "tmux 3.4\n"},
	}}
	known := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(known, []byte("host ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := New(host.New(map[string]host.Host{"h": {Address: "example", Port: 22, User: "u", ShellBackend: "tmux", Policy: policy.Policy{Exec: true}}}), f, known)
	report := d.Run(context.Background(), "h")
	if check, ok := findCheck(report.Checks, "tmux"); !ok || check.Status != StatusOK || check.Message != "tmux 3.4" {
		t.Fatalf("tmux check: %+v", report.Checks)
	}
	if _, ok := findCheck(report.Checks, "zellij"); ok {
		t.Fatalf("zellij checked on a tmux host: %+v", report.Checks)
	}
	f.results = map[string]transport.ExecResult{`command -v tmux >/dev/null 2>&1 && tmux -V`: {ExitCode: 1}}
	report = d.Run(context.Background(), "h")
	if check, ok := findCheck(report.Checks, "tmux"); !ok || check.Status != StatusWarn || report.Failed() {
		t.Fatalf("missing tmux: %+v", report.Checks)
	}
}

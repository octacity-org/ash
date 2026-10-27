package transport

import (
	"fmt"
	"testing"
)

func TestValidateTreeAcceptsSafeTree(t *testing.T) {
	entries := []TreeEntry{
		{Path: "a/b", IsDir: true},
		{Path: "a/b/c.txt", Data: []byte("hello")},
		{Path: "top.txt", Data: []byte("x")},
	}
	if err := ValidateTree("/remote", entries); err != nil {
		t.Fatal(err)
	}
}

func TestValidateTreeRejectsUnsafe(t *testing.T) {
	cases := map[string][]TreeEntry{
		"absolute":      {{Path: "/etc/passwd", Data: []byte("x")}},
		"traversal":     {{Path: "../secret", Data: []byte("x")}},
		"dot segment":   {{Path: "a/./b", Data: []byte("x")}},
		"nul":           {{Path: "a\x00b", Data: []byte("x")}},
		"backslash":     {{Path: `a\b`, Data: []byte("x")}},
		"empty":         {{Path: "", Data: []byte("x")}},
		"duplicate":     {{Path: "a", IsDir: true}, {Path: "a", IsDir: true}},
		"type conflict": {{Path: "a", Data: []byte("x")}, {Path: "a/b", Data: []byte("y")}},
		"dir data":      {{Path: "a", IsDir: true, Data: []byte("x")}},
		"setuid mode":   {{Path: "a", Data: []byte("x"), Perm: 0o4755}},
	}
	for name, entries := range cases {
		if err := ValidateTree("/remote", entries); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestValidateTreeEnforcesLimits(t *testing.T) {
	if err := ValidateTree("/remote", []TreeEntry{{Path: "a", IsDir: true, Data: nil}}); err != nil {
		t.Fatal(err)
	}
	tooMany := make([]TreeEntry, MaxTreeEntries+1)
	for i := range tooMany {
		tooMany[i] = TreeEntry{Path: fmt.Sprintf("f%d", i), Data: []byte("x")}
	}
	if err := ValidateTree("/remote", tooMany); err == nil {
		t.Fatal("accepted too many entries")
	}
	big := []TreeEntry{{Path: "big", Data: make([]byte, MaxTreePayload+1)}}
	if err := ValidateTree("/remote", big); err == nil {
		t.Fatal("accepted oversized payload")
	}
	deep := "a"
	for i := 0; i < MaxTreeDepth; i++ {
		deep += "/a"
	}
	if err := ValidateTree("/remote", []TreeEntry{{Path: deep, IsDir: true}}); err == nil {
		t.Fatal("accepted too deep path")
	}
}

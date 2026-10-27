package transport

import (
	"fmt"
	"path"
	"strings"
)

// ValidateTree rejects a tree that cannot be written safely before the first
// remote mutation. Paths are relative, slash-separated, and never traverse up.
func ValidateTree(root string, entries []TreeEntry) error {
	if root == "" {
		return fmt.Errorf("tree root must not be empty")
	}
	if len(entries) > MaxTreeEntries {
		return fmt.Errorf("tree exceeds %d entries", MaxTreeEntries)
	}
	kinds := make(map[string]bool, len(entries))
	total := 0
	for _, e := range entries {
		if err := validateTreePath(e.Path); err != nil {
			return err
		}
		if depth := strings.Count(e.Path, "/") + 1; depth > MaxTreeDepth {
			return fmt.Errorf("tree path %q exceeds depth %d", e.Path, MaxTreeDepth)
		}
		if _, ok := kinds[e.Path]; ok {
			return fmt.Errorf("duplicate tree path %q", e.Path)
		}
		kinds[e.Path] = e.IsDir
		if e.Perm&^0o777 != 0 {
			return fmt.Errorf("tree path %q has unsupported mode %v", e.Path, e.Perm)
		}
		if e.IsDir {
			if len(e.Data) != 0 {
				return fmt.Errorf("directory %q must not carry data", e.Path)
			}
			continue
		}
		total += len(e.Data)
		if total > MaxTreePayload {
			return fmt.Errorf("tree exceeds %d byte payload", MaxTreePayload)
		}
	}
	for _, e := range entries {
		for prefix := parentPath(e.Path); prefix != ""; prefix = parentPath(prefix) {
			if isDir, ok := kinds[prefix]; ok && !isDir {
				return fmt.Errorf("type conflict: %q is a file but also a parent directory", prefix)
			}
		}
	}
	return nil
}

func validateTreePath(p string) error {
	if p == "" {
		return fmt.Errorf("tree path must not be empty")
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("tree path must not contain NUL")
	}
	if strings.Contains(p, `\`) {
		return fmt.Errorf("tree path %q must use forward slashes", p)
	}
	if path.IsAbs(p) {
		return fmt.Errorf("tree path %q must be relative", p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("tree path %q must be normalized", p)
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("tree path %q contains an invalid segment", p)
		}
	}
	return nil
}

func parentPath(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}

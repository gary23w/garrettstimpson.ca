package tool

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var (
	rgOnce     sync.Once
	rgResolved string
)

func RipgrepPath() string {
	if os.Getenv("NORMA_DISABLE_RIPGREP") != "" {
		return ""
	}
	rgOnce.Do(func() { rgResolved = resolveRipgrep() })
	return rgResolved
}

func EnsureRipgrep() string { return RipgrepPath() }

func resolveRipgrep() string {
	if p, err := exec.LookPath("rg"); err == nil {
		return p
	}
	if os.Getenv("NORMA_RIPGREP_NO_INSTALL") != "" {
		return ""
	}
	return installRipgrepViaNpm()
}

func installRipgrepViaNpm() string {
	if _, err := exec.LookPath("npm"); err != nil {
		return ""
	}
	cmd := exec.Command("npm", "install", "-g", "@vscode/ripgrep")
	if err := cmd.Run(); err != nil {
		return ""
	}
	if p, err := exec.LookPath("rg"); err == nil {
		return p
	}
	return npmGlobalRipgrep()
}

func npmGlobalRipgrep() string {
	out, err := exec.Command("npm", "root", "-g").Output()
	if err != nil {
		return ""
	}
	name := "rg"
	if runtime.GOOS == "windows" {
		name = "rg.exe"
	}
	p := filepath.Join(strings.TrimSpace(string(out)), "@vscode", "ripgrep", "bin", name)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}

type ripgrepReq struct {
	pattern, glob, typ, mode         string
	ignoreCase, multiline, showLines bool
	before, after                    int
	root                             string
	headLimit                        *int
	offset                           int
}

func runWithRipgrep(rg string, r ripgrepReq, tc *ToolContext) (Result, bool) {
	args := []string{"--color", "never"}
	if r.ignoreCase {
		args = append(args, "-i")
	}
	if r.multiline {
		args = append(args, "-U", "--multiline-dotall")
	}
	switch r.mode {
	case "files_with_matches":
		args = append(args, "-l")
	case "count":
		args = append(args, "-c")
	default:
		args = append(args, "--no-heading")
		if r.showLines {
			args = append(args, "-n")
		}
		if r.before > 0 {
			args = append(args, "-B", strconv.Itoa(r.before))
		}
		if r.after > 0 {
			args = append(args, "-A", strconv.Itoa(r.after))
		}
	}
	if r.glob != "" {
		args = append(args, "--glob", r.glob)
	}
	if r.typ != "" {
		if _, known := rgFileTypes[strings.ToLower(r.typ)]; known {
			args = append(args, "--type", r.typ)
		} else {
			args = append(args, "--glob", "*."+r.typ)
		}
	}

	dir, target := r.root, "."
	if st, err := os.Stat(r.root); err == nil && !st.IsDir() {
		dir, target = filepath.Dir(r.root), filepath.Base(r.root)
	}

	args = append(args, "-e", r.pattern, "--", target)

	cmd := exec.Command(rg, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return Text("No matches found"), true
		}
		return Result{}, false
	}
	trimmed := strings.TrimRight(string(out), "\n")
	if trimmed == "" {
		return Text("No matches found"), true
	}
	lines := strings.Split(trimmed, "\n")
	headLimit := 250
	if r.headLimit != nil {
		headLimit = *r.headLimit
	}
	kept, more := applyHeadOffset(lines, headLimit, r.offset)
	res := strings.Join(kept, "\n")
	if len(kept) > 0 {
		res += "\n"
	}
	if more > 0 {
		res += fmt.Sprintf("... [%d more result(s) — page with offset=%d, or head_limit=0 for all] ...\n", more, r.offset+len(kept))
	}
	return Text(Capture(tc, res)), true
}

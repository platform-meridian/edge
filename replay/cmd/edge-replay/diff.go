package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

func readResults(path string) (map[string]map[string]any, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	m := map[string]map[string]any{}
	var keys []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<30)
	for sc.Scan() {
		var r map[string]any
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, nil, err
		}
		k := r["k"].(string)
		m[k] = r
		keys = append(keys, k)
	}
	return m, keys, sc.Err()
}

func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			flatten(prefix+"."+k, x, out)
		}
	case []any:
		for i, x := range t {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), x, out)
		}
		out[prefix+".len"] = fmt.Sprint(len(t))
	default:
		b, _ := json.Marshal(t)
		out[prefix] = string(b)
	}
}

var generic = regexp.MustCompile(`\[\d+\]|\.W\d+`)

// informational paths differ by timing alone and are reported, not counted.
func informational(path string) bool { return strings.HasPrefix(path, ".stream.progress") }

type group struct {
	n       int
	example string
}

type knownDiff struct {
	method, why string
	path        *regexp.Regexp
}

// readKnown reads "method<TAB>path regexp<TAB>why" lines: differences understood
// and accepted, reported as explained rather than divergent.
func readKnown(path string) ([]knownDiff, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []knownDiff
	for _, l := range strings.Split(string(b), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.SplitN(l, "\t", 3)
		if len(f) != 3 {
			return nil, fmt.Errorf("%s: want 3 tab-separated fields: %q", path, l)
		}
		re, err := regexp.Compile("^" + f[1] + "$")
		if err != nil {
			return nil, err
		}
		out = append(out, knownDiff{method: f[0], path: re, why: f[2]})
	}
	return out, nil
}

func explain(known []knownDiff, method, path string) string {
	for _, k := range known {
		if strings.HasSuffix(method, k.method) && k.path.MatchString(path) {
			return k.why
		}
	}
	return ""
}

func cmdDiff(args []string) (int, error) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	knownPath := fs.String("known", "", "explained differences (method, path regexp, why)")
	fs.Parse(args)
	args = fs.Args()
	if len(args) != 2 {
		return 0, fmt.Errorf("diff [-known f] <a.jsonl> <b.jsonl>")
	}
	known, err := readKnown(*knownPath)
	if err != nil {
		return 0, err
	}
	a, keys, err := readResults(args[0])
	if err != nil {
		return 0, err
	}
	b, bkeys, err := readResults(args[1])
	if err != nil {
		return 0, err
	}
	for _, k := range bkeys {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	groups, info, explained := map[string]*group{}, map[string]*group{}, map[string]*group{}
	same, divergent := 0, 0
	for _, k := range keys {
		ra, rb := a[k], b[k]
		method := ""
		if ra != nil {
			method = ra["method"].(string)
		} else {
			method = rb["method"].(string)
		}
		if ra == nil || rb == nil {
			g := groups[method+" only in one"]
			if g == nil {
				g = &group{example: k}
				groups[method+" only in one"] = g
			}
			g.n++
			divergent++
			continue
		}
		fa, fb := map[string]string{}, map[string]string{}
		flatten("", ra, fa)
		flatten("", rb, fb)
		var paths []string
		var detail []string
		infoOnly, allExplained := true, true
		whys := map[string]bool{}
		for p := range union(fa, fb) {
			if fa[p] == fb[p] {
				continue
			}
			paths = append(paths, p)
			if !informational(p) {
				infoOnly = false
				why := explain(known, method, generic.ReplaceAllString(p, "[]"))
				if why == "" {
					allExplained = false
				}
				whys[why] = true
			}
		}
		if len(paths) == 0 {
			same++
			continue
		}
		sort.Strings(paths)
		gp := map[string]bool{}
		for _, p := range paths {
			gp[generic.ReplaceAllString(p, "[]")] = true
			if len(detail) < 4 {
				detail = append(detail, fmt.Sprintf("%s: %s | %s", p, trunc(fa[p]), trunc(fb[p])))
			}
		}
		var gps []string
		for p := range gp {
			gps = append(gps, p)
		}
		sort.Strings(gps)
		if len(gps) > 4 {
			gps = append(gps[:4], "...")
		}
		key := method + " " + strings.Join(gps, " ")
		target := groups
		switch {
		case infoOnly:
			target = info
		case allExplained:
			target = explained
			var ws []string
			for w := range whys {
				ws = append(ws, w)
			}
			sort.Strings(ws)
			key = method + ": " + strings.Join(ws, "; ")
		default:
			divergent++
		}
		g := target[key]
		if g == nil {
			g = &group{example: k + "\n      " + strings.Join(detail, "\n      ")}
			target[key] = g
		}
		g.n++
		if infoOnly || allExplained {
			same++
		}
	}
	fmt.Printf("%d of %d results identical or explained, %d divergent\n", same, len(keys), divergent)
	print := func(title string, gs map[string]*group) {
		var ks []string
		for k := range gs {
			ks = append(ks, k)
		}
		sort.Slice(ks, func(i, j int) bool { return gs[ks[i]].n > gs[ks[j]].n })
		for _, k := range ks {
			fmt.Printf("%s %5d  %s\n    e.g. %s\n", title, gs[k].n, k, gs[k].example)
		}
	}
	print("DIVERGENT", groups)
	print("explained", explained)
	print("timing   ", info)
	return divergent, nil
}

func union(a, b map[string]string) map[string]bool {
	u := map[string]bool{}
	for k := range a {
		u[k] = true
	}
	for k := range b {
		u[k] = true
	}
	return u
}

func trunc(s string) string {
	if s == "" {
		return "<absent>"
	}
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

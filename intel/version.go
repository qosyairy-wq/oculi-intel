package intel

import (
	"regexp"
	"strconv"
	"strings"
)

// Version comparison never uses lexical or floating-point ordering.
// A version is accepted only when every part can be interpreted; anything else
// is reported as incomparable so callers return UNKNOWN instead of guessing.

// Scheme names.
const (
	SchemeDotted  = "dotted"  // numeric segments with an optional pre-release tag
	SchemeWindows = "windows" // 10.0.<build>.<UBR>; comparisons require the same build branch
	SchemeOpenSSL = "openssl" // 1.0.1g / 0.9.8za / 3.0.13: numeric parts plus an optional letter patch suffix
)

var opensslRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+){1,3})([a-z]{1,2})?$`)

// parseOpenSSL parses OpenSSL-style versions. The letter suffix is a patch
// level that sorts after the bare version ("" < "a" < ... < "z" < "za" < "zb").
// Pre-release tags (beta1, -pre2) are not accepted: they cannot be confused
// with a patch letter, so they are reported as incomparable.
func parseOpenSSL(s string) (Version, string, bool) {
	m := opensslRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return Version{}, "", false
	}
	v, ok := ParseVersion(m[1])
	return v, m[2], ok
}

// Version is a parsed version.
type Version struct {
	Raw    string
	Nums   []uint64
	Pre    int    // 0 = release; -1 rc, -2 beta, -3 alpha, -4 dev/preview
	PreNum uint64 // number after the pre-release tag
}

var (
	dottedRe = regexp.MustCompile(`^v?([0-9]+(?:[._][0-9]+)*)(?:[-._]?(alpha|beta|preview|pre|dev|rc|a|b|c)[-._]?([0-9]+)?)?$`)
	preRank  = map[string]int{"rc": -1, "c": -1, "beta": -2, "b": -2, "alpha": -3, "a": -3, "pre": -4, "preview": -4, "dev": -4}
)

// ParseVersion parses a dotted version such as "126.0.6478.127", "24.07",
// "3.13.0a1", "2.6.0-rc2" or "v20.11.1". Segments must be at most 18 digits.
func ParseVersion(s string) (Version, bool) {
	raw := s
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 64 {
		return Version{}, false
	}
	m := dottedRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	parts := strings.FieldsFunc(m[1], func(r rune) bool { return r == '.' || r == '_' })
	v := Version{Raw: raw}
	for _, p := range parts {
		if len(p) > 18 {
			return Version{}, false
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return Version{}, false
		}
		v.Nums = append(v.Nums, n)
	}
	if m[2] != "" {
		v.Pre = preRank[m[2]]
		if m[3] != "" {
			n, err := strconv.ParseUint(m[3], 10, 64)
			if err != nil {
				return Version{}, false
			}
			v.PreNum = n
		}
	}
	return v, true
}

// CompareVersions compares two version strings under a scheme.
// ok=false means the comparison cannot be made reliably.
func CompareVersions(a, b, scheme string) (cmp int, ok bool, why string) {
	if scheme == SchemeOpenSSL {
		va, la, oka := parseOpenSSL(a)
		vb, lb, okb := parseOpenSSL(b)
		if !oka || !okb {
			bad := a
			if oka {
				bad = b
			}
			return 0, false, "OpenSSL version " + quote(bad) + " cannot be interpreted"
		}
		if c := compareParsed(va, vb); c != 0 {
			return c, true, ""
		}
		switch {
		case la == lb:
			return 0, true, ""
		case len(la) != len(lb) && (la == "" || lb == ""):
			if la == "" {
				return -1, true, ""
			}
			return 1, true, ""
		case la < lb: // equal-length or z-prefixed ("z" < "za"): byte order is correct
			return -1, true, ""
		default:
			return 1, true, ""
		}
	}
	va, oka := ParseVersion(a)
	vb, okb := ParseVersion(b)
	if !oka || !okb {
		bad := a
		if oka {
			bad = b
		}
		return 0, false, "version " + quote(bad) + " cannot be interpreted"
	}
	if scheme == SchemeWindows {
		if len(va.Nums) != 4 || len(vb.Nums) != 4 || va.Pre != 0 || vb.Pre != 0 {
			return 0, false, "Windows build comparison needs four numeric parts"
		}
		if va.Nums[0] != vb.Nums[0] || va.Nums[1] != vb.Nums[1] || va.Nums[2] != vb.Nums[2] {
			return 0, false, "Windows builds " + quote(a) + " and " + quote(b) + " are on different build branches"
		}
	}
	return compareParsed(va, vb), true, ""
}

func compareParsed(a, b Version) int {
	n := len(a.Nums)
	if len(b.Nums) > n {
		n = len(b.Nums)
	}
	for i := 0; i < n; i++ {
		var x, y uint64
		if i < len(a.Nums) {
			x = a.Nums[i]
		}
		if i < len(b.Nums) {
			y = b.Nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	if a.Pre != b.Pre {
		if a.Pre < b.Pre {
			return -1
		}
		return 1
	}
	if a.PreNum != b.PreNum {
		if a.PreNum < b.PreNum {
			return -1
		}
		return 1
	}
	return 0
}

var numPrefix = regexp.MustCompile(`^v?([0-9]+(?:\.[0-9]+)*)`)

// compareDecisive is CompareVersions plus one sound fallback for records whose
// version strings OCULI cannot fully interpret (e.g. "6.0.0_build_34685",
// "2010-06-01", "0.8.6a" in old NVD entries): when the leading numeric parts
// already differ, the order is certain whatever follows. 26.0.0 vs
// "6.0.0_build_34685" → greater; 6.0.0 vs the same string → still undecided.
func compareDecisive(a, b, scheme string) (int, bool, string) {
	c, ok, why := CompareVersions(a, b, scheme)
	if ok || scheme == SchemeWindows {
		return c, ok, why
	}
	va, oka := ParseVersion(a)
	if scheme == SchemeOpenSSL {
		va, _, oka = parseOpenSSL(a)
	}
	m := numPrefix.FindStringSubmatch(strings.ToLower(strings.TrimSpace(b)))
	if !oka || m == nil {
		return 0, false, why
	}
	for i, p := range strings.Split(m[1], ".") {
		if len(p) > 18 {
			return 0, false, why
		}
		y, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return 0, false, why
		}
		var x uint64
		if i < len(va.Nums) {
			x = va.Nums[i]
		}
		if x != y {
			if x < y {
				return -1, true, ""
			}
			return 1, true, ""
		}
	}
	return 0, false, why
}

// Bound is one side of a version range.
type Bound struct {
	Version   string
	Inclusive bool
}

// InRange evaluates start <= v <= end with the given inclusivity.
// Empty bound versions mean unbounded.
func InRange(v string, start, end Bound, scheme string) (Tri, string) {
	if start.Version == "-" || start.Version == "*" || (start.Version == "0" && start.Inclusive) {
		start = Bound{} // NVD uses "-" / "*" / ">= 0" for "from the first version"
	}
	if end.Version == "*" {
		end = Bound{}
	}
	if start.Version != "" {
		c, ok, why := compareDecisive(v, start.Version, scheme)
		if !ok {
			return Unknown, why
		}
		if c < 0 || (c == 0 && !start.Inclusive) {
			return False, "installed " + v + " is below the affected range start " + boundText(start, true)
		}
	}
	if end.Version != "" {
		c, ok, why := compareDecisive(v, end.Version, scheme)
		if !ok {
			return Unknown, why
		}
		if c > 0 || (c == 0 && !end.Inclusive) {
			return False, "installed " + v + " is outside the affected range end " + boundText(end, false)
		}
	}
	return True, "installed " + v + " is within " + rangeText(start, end)
}

func boundText(b Bound, start bool) string {
	switch {
	case start && b.Inclusive:
		return ">= " + b.Version
	case start:
		return "> " + b.Version
	case b.Inclusive:
		return "<= " + b.Version
	default:
		return "< " + b.Version
	}
}

func rangeText(start, end Bound) string {
	var p []string
	if start.Version != "" {
		p = append(p, boundText(start, true))
	}
	if end.Version != "" {
		p = append(p, boundText(end, false))
	}
	if len(p) == 0 {
		return "all versions"
	}
	return strings.Join(p, " and ")
}

func quote(s string) string { return `"` + s + `"` }

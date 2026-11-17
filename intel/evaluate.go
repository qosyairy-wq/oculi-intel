package intel

import (
	"regexp"
	"strconv"
	"strings"
)

// Finding statuses (spec §8).
const (
	StatusAffected            = "AFFECTED"
	StatusPotentiallyAffected = "POTENTIALLY_AFFECTED"
	StatusNotAffected         = "NOT_AFFECTED"
	StatusUnknown             = "UNKNOWN"
	StatusUnmapped            = "UNMAPPED"
	StatusNoKnownCVE          = "NO_KNOWN_CVE_FOUND"
)

// EvalContext is everything known about the endpoint.
type EvalContext struct {
	Identities        []*Identity // mapped applications and the OS
	EndpointIsWindows bool
	// OSBuild is the Windows CurrentBuild even when the OS itself could not be
	// mapped (e.g. Insider builds). It lets release-specific prerequisites such as
	// "Windows 10 1607" be ruled out instead of becoming UNKNOWN.
	OSBuild int
}

func (ctx *EvalContext) os() *Identity {
	for _, id := range ctx.Identities {
		if id.IsOS {
			return id
		}
	}
	return nil
}

// SourceVerdict is one source's conclusion for one identity.
type SourceVerdict struct {
	Source         string   `json:"source"`
	Result         string   `json:"result"` // true/false/unknown
	Trusted        bool     `json:"trusted"`
	Detail         []string `json:"detail"`
	FixedIn        []string `json:"fixedIn,omitempty"`         // first non-affected versions stated by the source
	AffectedUpTo   []string `json:"affectedThrough,omitempty"` // inclusive upper bounds stated by the source
	ExactOnlyBelow bool     `json:"exactOnlyBelow,omitempty"`
	// NoVersionInfo: the source is UNKNOWN only because it names the product
	// without any version information ("*" with no range, or "-").
	NoVersionInfo bool `json:"noVersionInfo,omitempty"`
	// ExactOtherLine: only exact versions are listed, all "newer" than the
	// installed one but none sharing its major version (other numbering).
	ExactOtherLine bool `json:"exactOtherLine,omitempty"`
	tri            Tri
}

// Verdict is the applicability conclusion for one (software, CVE) pair.
type Verdict struct {
	CVEID    string          `json:"cve"`
	Status   string          `json:"status"`
	Primary  string          `json:"primarySource"`
	Conflict bool            `json:"conflict,omitempty"`
	Reasons  []string        `json:"reasons"`
	Sources  []SourceVerdict `json:"sources"`
}

// References reports whether the CVE names this identity in any source.
func References(c *CVE, id *Identity) bool {
	return nvdReferences(c, id) || adpReferences(c, id) || cnaReferences(c, id)
}

func (id *Identity) hasCPE(cp CPE) bool {
	for _, r := range id.CPEs {
		if r.Part == cp.Part && r.Vendor == cp.Vendor && r.Product == cp.Product {
			return true
		}
	}
	return false
}

func nvdReferences(c *CVE, id *Identity) bool {
	for _, cfg := range c.NVD {
		for _, n := range cfg.Nodes {
			for i := range n.Matches {
				m := &n.Matches[i]
				if !m.Vulnerable {
					continue
				}
				if cp, err := m.parsedCPE(); err == nil && id.hasCPE(cp) {
					return true
				}
			}
		}
	}
	return false
}

func adpReferences(c *CVE, id *Identity) bool {
	for _, rs := range c.ADP {
		if rangeSetHasCPE(rs, id) {
			return true
		}
	}
	return false
}

func rangeSetHasCPE(rs RangeSet, id *Identity) bool {
	for _, s := range rs.CPEs {
		cp, err := ParseCPE(s)
		if err != nil {
			continue
		}
		for _, r := range id.CPEs {
			if r.Part != cp.Part || r.Vendor != cp.Vendor || r.Product != cp.Product {
				continue
			}
			if r.Shared && (anyValue(cp.SwEdition) || cp.SwEdition != id.SwEdition) {
				continue // edition-less data on a CPE shared by several editions
			}
			return true
		}
	}
	return false
}

func cnaReferences(c *CVE, id *Identity) bool {
	for _, rs := range c.CNA {
		if cnaNameMatch(rs, id) {
			return true
		}
	}
	return false
}

func cnaNameMatch(rs RangeSet, id *Identity) bool {
	v, p := NormalizeName(rs.Vendor), NormalizeName(rs.Product)
	for _, a := range id.CNA {
		if a.Vendor == v && a.Product == p {
			return true
		}
	}
	return false
}

// Evaluate decides applicability of c to the identity id within ctx.
// ok=false means the CVE does not reference this identity at all.
func Evaluate(c *CVE, id *Identity, ctx *EvalContext) (Verdict, bool) {
	v := Verdict{CVEID: c.ID}
	if !References(c, id) {
		return v, false
	}
	if c.State == "REJECTED" {
		v.Status = StatusNotAffected
		v.Reasons = []string{"CVE record is REJECTED; no finding is produced"}
		return v, true
	}
	if !id.Supported {
		v.Status = StatusUnknown
		v.Reasons = []string{id.UnsupportedReason}
		return v, true
	}
	if nvdReferences(c, id) {
		v.Sources = append(v.Sources, evalNVD(c, id, ctx))
	}
	var adp, cna []RangeSet
	for _, rs := range c.ADP {
		if rangeSetHasCPE(rs, id) {
			adp = append(adp, rs)
		}
	}
	for _, rs := range c.CNA {
		if cnaNameMatch(rs, id) {
			cna = append(cna, rs)
		}
	}
	if len(adp) > 0 {
		sv := evalRangeSets(adp, id)
		sv.Source, sv.Trusted = "CISA ADP", true
		v.Sources = append(v.Sources, sv)
	}
	if len(cna) > 0 {
		sv := evalRangeSets(cna, id)
		sv.Source = "CNA"
		if id.CNATrust == "primary" {
			sv.Source = "Vendor (CNA)"
		}
		sv.Trusted = id.CNATrust == "primary" || id.CNATrust == "crosscheck"
		v.Sources = append(v.Sources, sv)
	}
	classify(&v, c, id)
	return v, true
}

// evalRangeSets combines several matching product entries of one source
// (e.g. MSRC lists the same Windows release once per platform): TRUE if any
// entry says affected, else UNKNOWN if any is unknown, else FALSE.
func evalRangeSets(sets []RangeSet, id *Identity) SourceVerdict {
	var out SourceVerdict
	var rs []Tri
	noVer, otherUnknown := false, false
	for _, s := range sets {
		sv := evalRangeSet(s, id)
		rs = append(rs, sv.tri)
		if sv.tri == Unknown {
			if sv.NoVersionInfo {
				noVer = true
			} else {
				otherUnknown = true
			}
		}
		label := s.Product
		if len(s.Platforms) > 0 {
			label += " [" + strings.Join(s.Platforms, ", ") + "]"
		}
		for _, d := range sv.Detail {
			if len(out.Detail) < 12 {
				out.Detail = append(out.Detail, label+": "+d)
			}
		}
		if sv.tri != False || len(sets) == 1 {
			out.FixedIn = append(out.FixedIn, sv.FixedIn...)
			out.AffectedUpTo = append(out.AffectedUpTo, sv.AffectedUpTo...)
		}
	}
	out.tri = triOr(rs)
	out.Result = out.tri.String()
	out.NoVersionInfo = out.tri == Unknown && noVer && !otherUnknown
	out.FixedIn, out.AffectedUpTo = uniq(out.FixedIn), uniq(out.AffectedUpTo)
	return out
}

func classify(v *Verdict, c *CVE, id *Identity) {
	// Choose the primary source.
	var primary *SourceVerdict
	pick := func(name string) *SourceVerdict {
		for i := range v.Sources {
			if strings.HasPrefix(v.Sources[i].Source, name) {
				return &v.Sources[i]
			}
		}
		return nil
	}
	if id.CNATrust == "primary" {
		primary = pick("Vendor")
	}
	if primary == nil {
		primary = pick("NVD")
	}
	if primary == nil {
		primary = pick("CISA ADP")
	}
	if primary == nil {
		primary = pick("Vendor")
	}
	if primary == nil {
		primary = pick("CNA")
	}
	if primary == nil {
		v.Status = StatusUnknown
		v.Reasons = append(v.Reasons, "no evaluable source")
		return
	}
	if primary.tri == Unknown && primary.NoVersionInfo {
		for i := range v.Sources {
			if o := &v.Sources[i]; o != primary && o.Trusted && o.tri != Unknown {
				v.Reasons = append(v.Reasons, primary.Source+" gives no version information for this product; "+o.Source+" is used")
				primary = o
				break
			}
		}
	}
	v.Primary = primary.Source
	// Conflict detection among trusted sources with definite answers.
	sawTrue, sawFalse := false, false
	for _, s := range v.Sources {
		if !s.Trusted {
			continue
		}
		switch s.tri {
		case True:
			sawTrue = true
		case False:
			sawFalse = true
		}
	}
	if sawTrue && sawFalse {
		v.Conflict = true
		v.Status = StatusPotentiallyAffected
		var parts []string
		for _, s := range v.Sources {
			if s.Trusted && s.tri != Unknown {
				word := "not affected"
				if s.tri == True {
					word = "affected"
				}
				parts = append(parts, s.Source+" says "+word)
			}
		}
		v.Reasons = append(v.Reasons, "Sources disagree: "+strings.Join(parts, "; ")+". Verify against the vendor advisory.")
		return
	}
	switch primary.tri {
	case True:
		v.Status = StatusAffected
		if !primary.Trusted {
			v.Status = StatusPotentiallyAffected
			v.Reasons = append(v.Reasons, "Only free-text CNA data supports this result; product/version applicability is not structured")
		}
		if id.Auto {
			v.Status = StatusPotentiallyAffected
			v.Reasons = append(v.Reasons, "The product identity was matched automatically from the display name and publisher and is not verified by OCULI; confirm the product and its version before acting")
		} else if id.Confidence != "high" {
			v.Status = StatusPotentiallyAffected
			v.Reasons = append(v.Reasons, "Software identity confidence is "+id.Confidence)
		}
		if c.Disputed {
			v.Status = StatusPotentiallyAffected
			v.Reasons = append(v.Reasons, "The CVE record is tagged DISPUTED")
		}
	case Unknown:
		v.Status = StatusPotentiallyAffected
		if primary.NoVersionInfo && !sawTrue && !sawFalse {
			if c.KEV == nil {
				// No evidence either way: reported as UNKNOWN (counted, not a finding).
				v.Status = StatusUnknown
				v.Reasons = append(v.Reasons, "The NVD record names this product without any version information, so applicability cannot be evaluated")
				return
			}
			v.Reasons = append(v.Reasons, "The NVD record names this product without version information, and the CVE is known to be exploited (CISA KEV)")
			return
		}
		v.Reasons = append(v.Reasons, "Applicability could not be determined from the available evidence")
	case False:
		v.Status = StatusNotAffected
		if primary.ExactOnlyBelow {
			v.Status = StatusPotentiallyAffected
			v.Reasons = append(v.Reasons, "The source lists only specific affected versions of this release line and the installed version is older than all of them; older versions are not explicitly cleared")
		} else if primary.ExactOtherLine {
			// e.g. Visio build 16.0.x vs listed product years "2007"/"2010": the
			// listed versions use another numbering, so nothing can be concluded.
			v.Status = StatusUnknown
			v.Reasons = append(v.Reasons, "The source lists only specific versions, none from the installed version's release line (different numbering), so applicability cannot be evaluated")
		}
	}
}

// ---------------- NVD configuration evaluation ----------------

type nvdEval struct {
	id      *Identity
	ctx     *EvalContext
	detail  []string
	fixedIn []string
	upTo    []string
	exact   []string // exact vulnerable versions referencing the focus
	ranged  bool
	seen    map[string]bool
	// unknown causes of focus criteria
	lastNoVersion bool
	unkNoVersion  int
	unkOther      int
}

func (e *nvdEval) note(s string) {
	if !e.seen[s] && len(e.detail) < 12 {
		e.seen[s] = true
		e.detail = append(e.detail, s)
	}
}

func evalNVD(c *CVE, id *Identity, ctx *EvalContext) SourceVerdict {
	// Ambiguous identities are evaluated once per CPE alternative; results must agree.
	groups := [][]CPERef{id.CPEs}
	if id.Ambiguous {
		groups = nil
		for _, r := range id.CPEs {
			groups = append(groups, []CPERef{r})
		}
	}
	var results []Tri
	e := &nvdEval{id: id, ctx: ctx, seen: map[string]bool{}}
	for _, g := range groups {
		focus := *id
		focus.CPEs = g
		e.id = &focus
		var cfgResults []Tri
		for _, cfg := range c.NVD {
			if !configReferences(cfg, &focus) {
				continue
			}
			cfgResults = append(cfgResults, e.config(cfg))
		}
		results = append(results, triOr(cfgResults)) // no referencing config → FALSE for this alternative
	}
	res := results[0]
	for _, r := range results[1:] {
		if r != res {
			e.note("Result differs between possible product editions (e.g. Reader vs. Acrobat); edition not determined")
			res = Unknown
			break
		}
	}
	sv := SourceVerdict{Source: "NVD", Trusted: true, tri: res, Result: res.String(), Detail: e.detail, FixedIn: uniq(e.fixedIn), AffectedUpTo: uniq(e.upTo)}
	sv.NoVersionInfo = res == Unknown && e.unkNoVersion > 0 && e.unkOther == 0
	if c.NVDStatus != "" {
		sv.Detail = append([]string{"NVD analysis status: " + c.NVDStatus}, sv.Detail...)
	}
	if res == False && !e.ranged && len(e.exact) > 0 && id.Version != "" {
		below, sameLine := true, false
		iv, _ := ParseVersion(id.Version)
		for _, x := range e.exact {
			cmp, ok, _ := compareDecisive(id.Version, x, id.Scheme)
			if !ok || cmp >= 0 {
				below = false
				break
			}
			if xv, ok := ParseVersion(x); ok && len(xv.Nums) > 0 && len(iv.Nums) > 0 && xv.Nums[0] == iv.Nums[0] {
				sameLine = true
			} else if m := numPrefix.FindStringSubmatch(x); m != nil && len(iv.Nums) > 0 && strings.SplitN(m[1], ".", 2)[0] == itoa(int(iv.Nums[0])) {
				sameLine = true
			}
		}
		sv.ExactOnlyBelow = below && sameLine
		sv.ExactOtherLine = below && !sameLine
	}
	return sv
}

func configReferences(cfg Config, id *Identity) bool {
	for _, n := range cfg.Nodes {
		if nodeReferences(n, id) {
			return true
		}
	}
	return false
}

func nodeReferences(n Node, id *Identity) bool {
	for i := range n.Matches {
		m := &n.Matches[i]
		if m.Vulnerable {
			if cp, err := m.parsedCPE(); err == nil && id.hasCPE(cp) {
				return true
			}
		}
	}
	return false
}

func (e *nvdEval) config(cfg Config) Tri {
	var rs []Tri
	for _, n := range cfg.Nodes {
		r := e.node(n)
		if n.Negate {
			r = r.Not()
		}
		rs = append(rs, r)
	}
	var out Tri
	if cfg.Operator == "AND" {
		out = triAnd(rs)
	} else {
		out = triOr(rs)
	}
	if cfg.Negate {
		out = out.Not()
	}
	return out
}

func (e *nvdEval) node(n Node) Tri {
	focus := nodeReferences(n, e.id) && n.Operator != "AND"
	var rs []Tri
	for i := range n.Matches {
		m := n.Matches[i]
		cp, err := n.Matches[i].parsedCPE()
		if err != nil {
			rs = append(rs, Unknown)
			continue
		}
		if focus {
			// In a node naming the focus product, only the focus product's
			// vulnerable criteria decide this product's result.
			if !m.Vulnerable || !e.id.hasCPE(cp) {
				continue
			}
			e.lastNoVersion = false
			r := e.matchIdentity(m, cp, e.id, true)
			if r == Unknown {
				if e.lastNoVersion {
					e.unkNoVersion++
				} else {
					e.unkOther++
				}
			}
			rs = append(rs, r)
			continue
		}
		r := e.matchContext(m, cp)
		if r == Unknown {
			e.unkOther++
		}
		rs = append(rs, r)
	}
	if n.Operator == "AND" {
		return triAnd(rs)
	}
	return triOr(rs)
}

// matchContext evaluates a criterion against everything installed (platform prerequisites etc.).
func (e *nvdEval) matchContext(m Match, cp CPE) Tri {
	if cp.Part == "h" {
		e.note("Hardware prerequisite " + cp.Vendor + ":" + cp.Product + " is not inventoried on this PC")
		return False
	}
	if cp.Part == "o" && e.ctx.EndpointIsWindows {
		if cp.Vendor != "microsoft" {
			e.note("Platform " + cp.Vendor + ":" + cp.Product + " is not this Windows endpoint")
			return False
		}
		if cp.Product == "windows" {
			if !anyValue(cp.TargetHW) && cp.TargetHW != "-" {
				if os := e.ctx.os(); os != nil && os.Arch != "" {
					if normArch(cp.TargetHW) != os.Arch {
						e.note("Windows prerequisite is for " + cp.TargetHW)
						return False
					}
				} else {
					return Unknown
				}
			}
			e.note("Windows platform prerequisite is satisfied")
			return True
		}
		os := e.ctx.os()
		if os == nil {
			if builds, ok := releaseBuilds(cp); ok && e.ctx.OSBuild > 0 {
				for _, b := range builds {
					if b == e.ctx.OSBuild {
						e.note("Windows release not identified; prerequisite " + cp.Product + " uses this PC's build number and cannot be ruled out")
						return Unknown
					}
				}
				e.note("Prerequisite " + cp.Product + " does not apply: this PC runs Windows build " + itoa(e.ctx.OSBuild))
				return False
			}
			e.note("Windows release not identified; release-specific prerequisite " + cp.Product + " cannot be checked")
			return Unknown
		}
		if !os.hasCPE(cp) {
			return False
		}
		return e.matchIdentity(m, cp, os, false)
	}
	var rs []Tri
	for _, id := range e.ctx.Identities {
		if id.hasCPE(cp) {
			rs = append(rs, e.matchIdentity(m, cp, id, false))
		}
	}
	return triOr(rs)
}

var windowsLikeTarget = regexp.MustCompile(`^(windows.*|win32|win64)$`)

// matchIdentity checks one CPE criterion against one installed identity.
// The version is checked first: a version that is certainly outside the
// criterion makes it FALSE whatever its other attributes (edition, update,
// language) say, because a criterion is the conjunction of all of them.
func (e *nvdEval) matchIdentity(m Match, cp CPE, id *Identity, focus bool) Tri {
	note := func(s string) {
		if focus {
			e.note(s)
		}
	}
	// target platform of the software
	if !anyValue(cp.TargetSW) && cp.TargetSW != "-" && !windowsLikeTarget.MatchString(cp.TargetSW) {
		note("Criterion applies to target platform " + quote(cp.TargetSW) + ", not Windows")
		return False
	}
	vt, noVersion := e.matchVersion(m, cp, id, focus)
	if vt == False {
		return False
	}
	var cs []Tri
	if !anyValue(cp.TargetHW) && cp.TargetHW != "-" {
		switch {
		case id.Arch == "":
			note("Criterion is specific to " + cp.TargetHW + " and the installed architecture is unknown")
			cs = append(cs, Unknown)
		case normArch(cp.TargetHW) != id.Arch:
			note("Criterion is for " + cp.TargetHW + "; installed is " + id.Arch)
			return False
		}
	}
	if !anyValue(cp.SwEdition) && !id.IgnoreSwEdition {
		want := cp.SwEdition
		have := id.SwEdition
		for _, r := range id.CPEs {
			if r.Vendor == cp.Vendor && r.Product == cp.Product && r.SwEdition != "" {
				have = r.SwEdition
			}
		}
		switch {
		case have == "" && windowsLikeTarget.MatchString(want) && e.ctx != nil && e.ctx.EndpointIsWindows:
			note("Criterion is for the Windows edition (" + quote(want) + "); this is a Windows PC")
		case have == "" && nonWindowsEdition[want]:
			note("Criterion is for the " + quote(want) + " edition, not Windows")
			return False
		case have == "":
			note("Criterion requires edition " + quote(want) + "; installed edition unknown")
			cs = append(cs, Unknown)
		case have != want:
			note("Criterion is for edition " + quote(want) + "; installed is " + quote(have))
			return False
		}
	}
	for _, f := range []struct{ name, v string }{{"edition", cp.Edition}, {"language", cp.Language}, {"other", cp.Other}} {
		if !anyValue(f.v) && f.v != "-" {
			note("Criterion constrains " + f.name + " = " + quote(f.v) + ", which the inventory does not record")
			cs = append(cs, Unknown)
		}
	}
	out := triAnd(append(cs, vt))
	if out == Unknown && noVersion && len(cs) == 0 {
		e.lastNoVersion = true
	}
	return out
}

var nonWindowsEdition = map[string]bool{"mac": true, "macos": true, "mac_os": true, "mac_os_x": true, "osx": true, "linux": true, "android": true, "ios": true, "iphone_os": true, "ipad": true}

// matchVersion evaluates the version part of a criterion. noVersion reports an
// UNKNOWN caused only by the record giving no version information.
func (e *nvdEval) matchVersion(m Match, cp CPE, id *Identity, focus bool) (Tri, bool) {
	note := func(s string) {
		if focus {
			e.note(s)
		}
	}
	hasRange := m.VSI != "" || m.VSE != "" || m.VEI != "" || m.VEE != ""
	if focus && m.Vulnerable {
		if hasRange || cp.Version == "*" {
			e.ranged = true
		}
	}
	ver := id.Version
	if hasRange {
		if ver == "" {
			note("Installed version unknown")
			return Unknown, false
		}
		start := Bound{Version: m.VSI, Inclusive: true}
		if m.VSE != "" {
			start = Bound{Version: m.VSE}
		}
		end := Bound{Version: m.VEE}
		if m.VEI != "" {
			end = Bound{Version: m.VEI, Inclusive: true}
		}
		if id.Scheme == SchemeWindows {
			start = windowsLower(start, ver)
		}
		r, why := InRange(ver, start, end, id.Scheme)
		note(why)
		if focus && r != False { // only the range the installed version falls into is relevant for remediation
			if m.VEE != "" {
				e.fixedIn = append(e.fixedIn, m.VEE)
			}
			if m.VEI != "" {
				e.upTo = append(e.upTo, m.VEI)
			}
		}
		return r, false
	}
	switch cp.Version {
	case "*", "":
		if !m.Vulnerable {
			return True, false
		}
		// NVD lists the product with every version and no range: the record does
		// not say which versions are affected or fixed (common in old records and
		// in records about earlier product generations, e.g. EdgeHTML Edge).
		note("NVD lists every version without a version range; affected/fixed versions are not stated")
		return Unknown, true
	case "-":
		if !m.Vulnerable {
			return True, false
		}
		note("Record gives no affected version information for this product")
		return Unknown, true
	}
	if ver == "" {
		note("Installed version unknown")
		return Unknown, false
	}
	target := cp.Version
	updateUnknown := false
	if !anyValue(cp.Update) && cp.Update != "-" {
		if preTag.MatchString(cp.Update) {
			target = cp.Version + cp.Update
		} else {
			updateUnknown = true
		}
	}
	if focus && m.Vulnerable {
		e.exact = append(e.exact, target)
	}
	cmp, ok, why := compareDecisive(ver, target, id.Scheme)
	if !ok {
		note(why)
		return Unknown, false
	}
	if cmp != 0 {
		return False, false
	}
	if updateUnknown {
		note("Installed " + ver + " equals listed version " + cp.Version + ", but the criterion constrains update " + quote(cp.Update) + ", which cannot be compared")
		return Unknown, false
	}
	note("Installed " + ver + " equals listed affected version " + target)
	return True, false
}

var preTag = regexp.MustCompile(`^(alpha|beta|rc|a|b|pre|preview|dev)[0-9]*$`)

// windowsLower drops a lower bound that is not on the installed build branch
// (vendors often write 10.0.0 or the previous branch's .0 as "from the beginning").
func windowsLower(b Bound, installed string) Bound {
	if b.Version == "" {
		return b
	}
	if _, ok, _ := CompareVersions(installed, b.Version, SchemeWindows); !ok {
		return Bound{}
	}
	return b
}

// ---------------- CVE 5.x range evaluation (CISA ADP / CNA) ----------------

var (
	freeLT     = regexp.MustCompile(`^(<=|<)\s*v?([0-9][0-9a-z._-]*)$`)
	freeEQ     = regexp.MustCompile(`^=\s*v?([0-9][0-9a-z._-]*)$`)
	freeRange  = regexp.MustCompile(`^>=\s*v?([0-9][0-9a-z._-]*)\s*,\s*(<=|<)\s*v?([0-9][0-9a-z._-]*)$`)
	freePrior  = regexp.MustCompile(`^v?([0-9][0-9a-z._-]*)\s+and\s+(earlier|prior|below|before)$`)
	parenthRe  = regexp.MustCompile(`\s*\([^)]*\)\s*$`)
	osPlatform = regexp.MustCompile(`(?i)\b(windows|macos|mac os|linux|android|ios|ipados|chrome ?os)\b`)
)

type rangeEntry struct {
	start, end Bound
	status     string
	why        string // non-empty → unusable entry
	changes    bool
}

func parseEntry(v VersionEntry) rangeEntry {
	r := rangeEntry{status: strings.ToLower(v.Status), changes: v.HasChanges}
	if v.VersionType == "git" {
		r.why = "commit-hash version ranges are not supported"
		return r
	}
	ver := strings.TrimSpace(strings.ToLower(v.Version))
	ver = parenthRe.ReplaceAllString(ver, "")
	lt := strings.TrimSpace(v.LessThan)
	lte := strings.TrimSpace(v.LessThanOrEqual)
	unbounded := ver == "" || ver == "0" || ver == "*" || ver == "unspecified" || ver == "n/a" || ver == "all"
	switch {
	case lt != "" || lte != "":
		if !unbounded {
			r.start = Bound{Version: ver, Inclusive: true}
		}
		if lt != "" {
			if strings.HasSuffix(lt, "*") {
				up, ok := wildcardUpper(lt)
				if !ok {
					r.why = "range end " + quote(lt) + " cannot be interpreted"
					return r
				}
				r.end = Bound{Version: up}
			} else {
				r.end = Bound{Version: lt}
			}
			// Some CNAs write "version X lessThan X" for "before X".
			if r.start.Version != "" && r.end.Version != "" {
				if c, ok, _ := CompareVersions(r.start.Version, r.end.Version, SchemeDotted); ok && c >= 0 {
					r.start = Bound{}
				}
			}
		} else {
			r.end = Bound{Version: lte, Inclusive: true}
		}
	case freeRange.MatchString(ver):
		m := freeRange.FindStringSubmatch(ver)
		r.start = Bound{Version: m[1], Inclusive: true}
		r.end = Bound{Version: m[3], Inclusive: m[2] == "<="}
	case freeLT.MatchString(ver):
		m := freeLT.FindStringSubmatch(ver)
		r.end = Bound{Version: m[2], Inclusive: m[1] == "<="}
	case freePrior.MatchString(ver):
		m := freePrior.FindStringSubmatch(ver)
		r.end = Bound{Version: m[1], Inclusive: true}
	case freeEQ.MatchString(ver):
		m := freeEQ.FindStringSubmatch(ver)
		r.start = Bound{Version: m[1], Inclusive: true}
		r.end = Bound{Version: m[1], Inclusive: true}
	case unbounded:
		r.why = "no version information (" + quote(v.Version) + ")"
	default:
		if _, ok := ParseVersion(ver); !ok {
			r.why = "version " + quote(v.Version) + " cannot be interpreted"
			return r
		}
		r.start = Bound{Version: ver, Inclusive: true}
		r.end = Bound{Version: ver, Inclusive: true}
	}
	return r
}

// wildcardUpper turns "4.*" into an exclusive upper bound "5".
func wildcardUpper(s string) (string, bool) {
	s = strings.TrimSuffix(strings.TrimSuffix(s, "*"), ".")
	p := strings.Split(s, ".")
	if len(p) == 0 || p[0] == "" {
		return "", false
	}
	n, err := strconv.ParseUint(p[len(p)-1], 10, 64)
	if err != nil {
		return "", false
	}
	p[len(p)-1] = strconv.FormatUint(n+1, 10)
	return strings.Join(p, "."), true
}

func evalRangeSet(rs RangeSet, id *Identity) (sv SourceVerdict) {
	set := func(t Tri, why string) SourceVerdict {
		sv.tri, sv.Result = t, t.String()
		if why != "" {
			sv.Detail = append(sv.Detail, why)
		}
		return sv
	}
	// Platform applicability
	if len(rs.Platforms) > 0 {
		if id.IsOS {
			if len(id.CNAPlatforms) == 0 {
				return set(Unknown, "Advisory is architecture-specific ("+strings.Join(rs.Platforms, ", ")+"); OS architecture unknown")
			}
			ok := false
			for _, p := range rs.Platforms {
				for _, want := range id.CNAPlatforms {
					if strings.EqualFold(strings.TrimSpace(p), want) {
						ok = true
					}
				}
			}
			if !ok {
				return set(False, "Advisory platforms ("+strings.Join(rs.Platforms, ", ")+") do not include this PC's architecture")
			}
		} else {
			osNamed, windows := false, false
			for _, p := range rs.Platforms {
				if osPlatform.MatchString(p) {
					osNamed = true
					if strings.Contains(strings.ToLower(p), "windows") {
						windows = true
					}
				}
			}
			if osNamed && !windows {
				return set(False, "Advisory platforms ("+strings.Join(rs.Platforms, ", ")+") do not include Windows")
			}
		}
	}
	if id.Version == "" {
		return set(Unknown, "Installed version unknown")
	}
	var anyAffected, anyUnaffected, anyUnknownMembership bool
	allAffectedBounded := true
	newerThanAll := true
	usable := 0
	defer func() {
		// Every version entry was a placeholder ("unspecified", "-", "publication"…):
		// the record carries no version information for this product.
		if usable == 0 && len(rs.Versions) > 0 && sv.tri == Unknown {
			sv.NoVersionInfo = true
		}
	}()
	for _, v := range rs.Versions {
		r := parseEntry(v)
		if r.why != "" {
			anyUnknownMembership = true
			allAffectedBounded = false
			sv.Detail = append(sv.Detail, "Version entry unusable: "+r.why)
			continue
		}
		usable++
		start := r.start
		if id.Scheme == SchemeWindows {
			start = windowsLower(start, id.Version)
		}
		in, why := InRange(id.Version, start, r.end, id.Scheme)
		if r.status != "affected" || r.end.Version == "" {
			allAffectedBounded = false
		}
		if r.end.Version != "" {
			if c, ok, _ := CompareVersions(id.Version, r.end.Version, id.Scheme); !ok || c < 0 || (c == 0 && r.end.Inclusive) {
				newerThanAll = false
			}
			if r.status == "affected" && in != False {
				if r.end.Inclusive {
					sv.AffectedUpTo = append(sv.AffectedUpTo, r.end.Version)
				} else {
					sv.FixedIn = append(sv.FixedIn, r.end.Version)
				}
			}
		} else {
			newerThanAll = false
		}
		switch in {
		case Unknown:
			anyUnknownMembership = true
			sv.Detail = append(sv.Detail, why)
		case True:
			if r.changes {
				anyUnknownMembership = true
				sv.Detail = append(sv.Detail, "Range has intermediate status changes; not evaluated")
				continue
			}
			sv.Detail = append(sv.Detail, why+" ("+r.status+")")
			switch r.status {
			case "affected":
				anyAffected = true
			case "unaffected":
				anyUnaffected = true
			default:
				anyUnknownMembership = true
			}
		}
	}
	sv.FixedIn, sv.AffectedUpTo = uniq(sv.FixedIn), uniq(sv.AffectedUpTo)
	switch {
	case anyAffected && anyUnaffected:
		return set(Unknown, "Record lists the installed version as both affected and unaffected")
	case anyAffected:
		return set(True, "")
	case anyUnaffected:
		return set(False, "")
	case anyUnknownMembership:
		return set(Unknown, "")
	}
	switch rs.DefaultStatus {
	case "unaffected":
		return set(False, "Installed version is outside every listed range; record default status is 'unaffected'")
	case "affected":
		return set(Unknown, "Record default status is 'affected' for versions outside the listed ranges; treated as unknown")
	}
	if allAffectedBounded && newerThanAll && len(rs.Versions) > 0 {
		return set(False, "Installed version is newer than every affected range listed (record has no default status)")
	}
	return set(Unknown, "Installed version is not covered by the record's version entries")
}

func uniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// releaseBuilds maps a Windows release CPE (product + version field) to the
// CurrentBuild number(s) of that release, for ruling prerequisites in or out.
func releaseBuilds(cp CPE) ([]int, bool) {
	for _, w := range windowsTable {
		if w.cpeProduct == cp.Product {
			return []int{w.build}, true
		}
	}
	r2 := cp.Version == "r2"
	anyV := anyValue(cp.Version)
	switch cp.Product {
	case "windows_7":
		return []int{7600, 7601}, true
	case "windows_8":
		return []int{9200}, true
	case "windows_8.1", "windows_rt_8.1":
		return []int{9600}, true
	case "windows_10_1511":
		return []int{10586}, true
	case "windows_10_1703":
		return []int{15063}, true
	case "windows_10_1709":
		return []int{16299}, true
	case "windows_10_1803":
		return []int{17134}, true
	case "windows_10_1903":
		return []int{18362}, true
	case "windows_10_1909":
		return []int{18363}, true
	case "windows_10_2004":
		return []int{19041}, true
	case "windows_10_20h2":
		return []int{19042}, true
	case "windows_10_21h1":
		return []int{19043}, true
	case "windows_server_2008":
		switch {
		case r2:
			return []int{7600, 7601}, true
		case anyV:
			return []int{6001, 6002, 6003, 7600, 7601}, true
		}
		return []int{6001, 6002, 6003}, true
	case "windows_server_2012":
		switch {
		case r2:
			return []int{9600}, true
		case anyV:
			return []int{9200, 9600}, true
		}
		return []int{9200}, true
	}
	return nil, false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

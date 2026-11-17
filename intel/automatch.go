package intel

import (
	"regexp"
	"sort"
	"strings"
)

// AutoMatcher proposes an NVD product identity for software that is not in the
// verified catalog. It is deliberately strict — no similarity scoring, no
// partial-word matches:
//
//  1. the publisher, after removing legal/corporate suffixes, must equal the
//     NVD vendor (word for word, or with spaces removed: "Palo Alto Networks" =
//     paloaltonetworks);
//  2. the display name, after removing version numbers, architecture and
//     language tags, must equal the NVD product, or vendor + product
//     ("VMware Workstation" = vmware + workstation), word for word;
//  3. exactly one NVD product may satisfy 1 and 2 (otherwise ambiguous → UNMAPPED);
//  4. the registry DisplayVersion must be an interpretable dotted version.
//
// Auto identities are labelled as unverified and their results are capped at
// POTENTIALLY_AFFECTED by the engine: a name/publisher match is evidence, not proof.
type AutoMatcher struct {
	byVendor map[string][]autoProduct // vendor key (no spaces) → products
}

type autoProduct struct {
	key          string // a:vendor:product
	vendor       string
	product      string
	vTokens      []string
	pTokens      []string
	vJoin, pJoin string
	cves         int
}

var (
	tokenRe    = regexp.MustCompile(`[a-z0-9+#]+`)
	versionTok = regexp.MustCompile(`^v?[0-9]+([.][0-9]+)*[a-z]?$`)
	corpSuffix = map[string]bool{"inc": true, "incorporated": true, "ltd": true, "limited": true, "llc": true, "llp": true, "co": true, "corp": true, "corporation": true, "company": true, "gmbh": true, "ag": true, "sa": true, "sas": true, "sarl": true, "bv": true, "nv": true, "srl": true, "spa": true, "pty": true, "plc": true, "sdn": true, "bhd": true, "kk": true, "oy": true, "ab": true, "as": true, "aps": true, "pte": true, "lp": true, "the": true}
	corpTail   = map[string]bool{"software": true, "technologies": true, "technology": true, "systems": true, "labs": true, "project": true, "foundation": true, "team": true, "group": true, "international": true, "development": true, "community": true}
	nameNoise  = map[string]bool{"x64": true, "x86": true, "amd64": true, "arm64": true, "win64": true, "win32": true, "64": true, "32": true, "bit": true, "64bit": true, "32bit": true, "version": true, "ver": true, "stable": true, "release": true}
	langTagRe  = regexp.MustCompile(`\(([a-z]{2}(-[a-z]{2,4})?|[a-z]{2}_[a-z]{2})\)|\b[a-z]{2}-[a-z]{2}\b`)
)

func tokens(s string) []string { return tokenRe.FindAllString(strings.ToLower(s), -1) }

// NewAutoMatcher indexes every application product that has CVEs in the snapshot.
func NewAutoMatcher(s *Snapshot) *AutoMatcher {
	m := &AutoMatcher{byVendor: map[string][]autoProduct{}}
	s.CPEKeys(func(key string, n int) {
		parts := strings.SplitN(key, ":", 3)
		if len(parts) != 3 || parts[0] != "a" {
			return
		}
		v, p := unescapeCPE(parts[1]), unescapeCPE(parts[2])
		ap := autoProduct{key: key, vendor: parts[1], product: parts[2], vTokens: tokens(strings.ReplaceAll(v, "_", " ")), pTokens: tokens(strings.ReplaceAll(p, "_", " ")), cves: n}
		if len(ap.vTokens) == 0 || len(ap.pTokens) == 0 {
			return
		}
		ap.vJoin, ap.pJoin = strings.Join(ap.vTokens, ""), strings.Join(ap.pTokens, "")
		m.byVendor[ap.vJoin] = append(m.byVendor[ap.vJoin], ap)
	})
	for k := range m.byVendor {
		l := m.byVendor[k]
		sort.Slice(l, func(i, j int) bool { return l[i].key < l[j].key })
	}
	return m
}

// vendorKeys returns the candidate vendor keys for a publisher: the full
// publisher (suffixes removed) and, if different, with trailing generic words
// ("Software", "Technologies", "Project", …) removed. Both are whole-publisher forms.
func vendorKeys(publisher string) []string {
	t := tokens(publisher)
	for len(t) > 0 && corpSuffix[t[len(t)-1]] {
		t = t[:len(t)-1]
	}
	for len(t) > 0 && corpSuffix[t[0]] { // "The …"
		t = t[1:]
	}
	if len(t) == 0 {
		return nil
	}
	out := []string{strings.Join(t, "")}
	u := t
	for len(u) > 1 && (corpTail[u[len(u)-1]] || corpSuffix[u[len(u)-1]]) {
		u = u[:len(u)-1]
	}
	if len(u) != len(t) {
		out = append(out, strings.Join(u, ""))
	}
	return out
}

// nameTokens strips versions, architecture and language tags from a display name.
func nameTokens(name string) []string {
	n := langTagRe.ReplaceAllString(strings.ToLower(name), " ")
	var out []string
	for _, t := range tokens(n) {
		if nameNoise[t] || versionTok.MatchString(t) {
			continue
		}
		out = append(out, t)
	}
	return out
}

func equalTokens(a, b []string) bool {
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

// Match proposes an identity, or returns a reason why none is proposed.
func (m *AutoMatcher) Match(in SoftwareInput) Resolution {
	if m == nil {
		return Resolution{}
	}
	if isStorePackage(in.Source) {
		return Resolution{Reason: "Microsoft Store/MSIX package: package versions are not product versions, so no automatic identity is proposed"}
	}
	vks := vendorKeys(in.Publisher)
	if len(vks) == 0 {
		return Resolution{Reason: "publisher missing, so no automatic identity can be proposed"}
	}
	nt := nameTokens(in.Name)
	if len(nt) == 0 {
		return Resolution{}
	}
	nJoin := strings.Join(nt, "")
	var hits []autoProduct
	seen := map[string]bool{}
	for _, vk := range vks {
		for _, ap := range m.byVendor[vk] {
			if seen[ap.key] {
				continue
			}
			ok := equalTokens(nt, ap.pTokens) || // "Steam" = valve:steam
				(len(nt) > len(ap.vTokens) && equalTokens(nt[:len(ap.vTokens)], ap.vTokens) && equalTokens(nt[len(ap.vTokens):], ap.pTokens)) || // "VMware Workstation"
				(len(nt) == 1 && nJoin == ap.pJoin) // single-word product written without separators ("WinSCP" = winscp)
			if ok {
				seen[ap.key] = true
				hits = append(hits, ap)
			}
		}
	}
	switch {
	case len(hits) == 0:
		return Resolution{}
	case len(hits) > 1:
		keys := make([]string, len(hits))
		for i, h := range hits {
			keys[i] = h.vendor + ":" + h.product
		}
		return Resolution{Reason: "several NVD products match the name and publisher (" + strings.Join(keys, ", ") + "); not mapped automatically"}
	}
	h := hits[0]
	ver := strings.TrimSpace(in.Version)
	if _, ok := ParseVersion(ver); !ok {
		return Resolution{Reason: "possible NVD product " + h.vendor + ":" + h.product + ", but the installed version " + quote(ver) + " cannot be interpreted, so it is not assessed"}
	}
	id := &Identity{SoftwareID: in.ID, CatalogID: "auto:" + h.vendor + ":" + h.product, Product: in.Name,
		CPEs:    []CPERef{{Part: "a", Vendor: h.vendor, Product: h.product}},
		Version: ver, VersionSource: "registry DisplayVersion", Scheme: SchemeDotted, Arch: in.Arch,
		Confidence: "auto", Supported: true, CNATrust: "fallback", Auto: true}
	id.Evidence = []string{
		"Automatic identity (not verified by OCULI): publisher " + quote(in.Publisher) + " equals NVD vendor " + quote(h.vendor),
		"Display name " + quote(in.Name) + " equals NVD product " + quote(h.product) + " after removing version, architecture and language tags",
		"Version " + ver + " read from registry DisplayVersion; the vendor's version scheme was not verified for this product",
		"Results for automatic identities are capped at POTENTIALLY_AFFECTED",
	}
	return Resolution{Mapped: true, Identity: id}
}

package intel

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed catalog.json
var embeddedCatalog []byte

// CPERef is one CPE identity a catalog product maps to.
type CPERef struct {
	Part      string `json:"part"`
	Vendor    string `json:"vendor"`
	Product   string `json:"product"`
	SwEdition string `json:"swEdition,omitempty"` // only for ambiguous/track-specific mappings
	// Shared marks a CPE used by several editions of a product (e.g. Firefox release and ESR).
	// Edition-less range data (CISA ADP / CNA) cannot be attributed through a shared CPE.
	Shared bool `json:"shared,omitempty"`
}

func (r CPERef) Key() string { return ProductKey(r.Part, r.Vendor, r.Product) }

// VendorProduct names a free-text CNA vendor/product pair (lower-case).
type VendorProduct struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

// CatalogEntry is one curated product identity.
type CatalogEntry struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	Names                []string        `json:"names"`
	Exclude              []string        `json:"exclude,omitempty"`
	Publishers           []string        `json:"publishers"`
	VersionFrom          string          `json:"versionFrom,omitempty"` // displayVersion (default) or name
	VersionRegex         string          `json:"versionRegex,omitempty"`
	Scheme               string          `json:"scheme,omitempty"`  // dotted (default) or openssl
	CPEMode              string          `json:"cpeMode,omitempty"` // alias (default) or ambiguous
	CPEs                 []CPERef        `json:"cpes"`
	SwEdition            string          `json:"swEdition,omitempty"`
	SwEditionFromVersion string          `json:"swEditionFromVersion,omitempty"`
	IgnoreSwEdition      bool            `json:"ignoreSwEdition,omitempty"`
	CNA                  []VendorProduct `json:"cna,omitempty"`
	CNATrust             string          `json:"cnaTrust,omitempty"` // primary, crosscheck, fallback
	Applicability        string          `json:"applicability,omitempty"`
	AllowStorePackage    bool            `json:"allowStorePackage,omitempty"` // only if the AppX package version is verified to equal the product version
	UnsupportedReason    string          `json:"unsupportedReason,omitempty"`
	Notes                string          `json:"notes,omitempty"`

	names, exclude, publishers []*regexp.Regexp
	versionRe                  *regexp.Regexp
}

// Catalog is the curated identity catalog.
type Catalog struct {
	Version string          `json:"version"`
	Notes   string          `json:"notes"`
	Entries []*CatalogEntry `json:"entries"`
	byID    map[string]*CatalogEntry
}

// LoadCatalog parses and validates a catalog. Any invalid entry fails the whole load.
func LoadCatalog(raw []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("invalid catalog: %w", err)
	}
	if c.Version == "" || len(c.Entries) == 0 {
		return nil, fmt.Errorf("catalog has no version or entries")
	}
	c.byID = map[string]*CatalogEntry{}
	compile := func(list []string, id string) ([]*regexp.Regexp, error) {
		var out []*regexp.Regexp
		for _, p := range list {
			re, err := regexp.Compile("(?i)" + p)
			if err != nil {
				return nil, fmt.Errorf("catalog %s: bad pattern %q: %w", id, p, err)
			}
			out = append(out, re)
		}
		return out, nil
	}
	for _, e := range c.Entries {
		if e.ID == "" || len(e.Names) == 0 || len(e.CPEs) == 0 {
			return nil, fmt.Errorf("catalog entry %q incomplete", e.ID)
		}
		if _, dup := c.byID[e.ID]; dup {
			return nil, fmt.Errorf("duplicate catalog entry %q", e.ID)
		}
		var err error
		if e.names, err = compile(e.Names, e.ID); err != nil {
			return nil, err
		}
		if e.exclude, err = compile(e.Exclude, e.ID); err != nil {
			return nil, err
		}
		if e.publishers, err = compile(e.Publishers, e.ID); err != nil {
			return nil, err
		}
		if e.VersionRegex != "" {
			if e.versionRe, err = regexp.Compile("(?i)" + e.VersionRegex); err != nil {
				return nil, fmt.Errorf("catalog %s: bad versionRegex: %w", e.ID, err)
			}
		}
		for i, r := range e.CPEs {
			r.Part, r.Vendor, r.Product = strings.ToLower(r.Part), strings.ToLower(r.Vendor), strings.ToLower(r.Product)
			if (r.Part != "a" && r.Part != "o") || r.Vendor == "" || r.Product == "" {
				return nil, fmt.Errorf("catalog %s: invalid CPE ref", e.ID)
			}
			e.CPEs[i] = r
		}
		for i, v := range e.CNA {
			e.CNA[i] = VendorProduct{Vendor: strings.ToLower(v.Vendor), Product: strings.ToLower(v.Product)}
		}
		switch e.CNATrust {
		case "", "fallback", "crosscheck", "primary":
		default:
			return nil, fmt.Errorf("catalog %s: invalid cnaTrust", e.ID)
		}
		c.byID[e.ID] = e
	}
	return &c, nil
}

// DefaultCatalog returns the catalog embedded in this build.
func DefaultCatalog() (*Catalog, error) { return LoadCatalog(embeddedCatalog) }

// Entry returns a catalog entry by ID.
func (c *Catalog) Entry(id string) *CatalogEntry { return c.byID[id] }

// AllCPEKeys lists every part:vendor:product the catalog maps to (plus Windows OS products).
func (c *Catalog) AllCPEKeys() []string {
	seen := map[string]bool{}
	for _, e := range c.Entries {
		for _, r := range e.CPEs {
			seen[r.Key()] = true
		}
	}
	for _, w := range windowsTable {
		seen[ProductKey("o", "microsoft", w.cpeProduct)] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SoftwareInput is the minimal inventory evidence identity resolution uses.
type SoftwareInput struct {
	ID        string
	Name      string
	Publisher string
	Version   string
	Arch      string // x64, x86, arm64 or ""
	Source    string // inventory source, e.g. "HKLM 64", "HKCU", "AppX"
}

// Identity is a resolved product identity with provenance.
type Identity struct {
	SoftwareID        string          `json:"softwareId"`
	CatalogID         string          `json:"catalogId"`
	Product           string          `json:"product"`
	CPEs              []CPERef        `json:"cpes"`
	Ambiguous         bool            `json:"ambiguousEdition,omitempty"`
	Version           string          `json:"version"`
	VersionSource     string          `json:"versionSource"`
	Scheme            string          `json:"scheme"`
	SwEdition         string          `json:"swEdition,omitempty"`
	IgnoreSwEdition   bool            `json:"-"`
	Arch              string          `json:"arch,omitempty"`
	Confidence        string          `json:"confidence"` // high, medium
	Supported         bool            `json:"supported"`
	UnsupportedReason string          `json:"unsupportedReason,omitempty"`
	CNA               []VendorProduct `json:"-"`
	CNATrust          string          `json:"cnaTrust,omitempty"`
	IsOS              bool            `json:"isOS,omitempty"`
	OSFamily          string          `json:"osFamily,omitempty"` // windows
	CNAPlatforms      []string        `json:"-"`                  // MSRC platform labels matching this OS
	Evidence          []string        `json:"evidence"`
	// Auto: identity proposed by the strict auto-matcher (AutoMatcher), not by a
	// verified catalog entry. Results for auto identities never exceed POTENTIALLY_AFFECTED.
	Auto bool `json:"auto,omitempty"`
}

// Resolution is the outcome of identity resolution.
type Resolution struct {
	Mapped   bool      `json:"mapped"`
	Identity *Identity `json:"identity,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	// Kind classifies UNMAPPED records: "component" (SDKs, runtimes, redistributables,
	// fonts, drivers, built-in Microsoft Store packages, …) or "product". It only
	// orders the review list; components are still NOT assessed and NOT declared safe.
	Kind string `json:"kind,omitempty"`
	// CatalogMiss: no catalog entry claims this name at all (as opposed to a catalog
	// product rejected for a publisher mismatch, exclusion or Store package). Only
	// these records may be offered to the strict auto-matcher.
	CatalogMiss bool `json:"-"`
}

var spaceRe = regexp.MustCompile(`\s+`)

// NormalizeName lower-cases, trims and collapses whitespace.
func NormalizeName(s string) string {
	return strings.TrimSpace(spaceRe.ReplaceAllString(strings.ToLower(s), " "))
}

// Resolve maps one installed software record to a catalog identity.
// It never falls back to fuzzy name similarity: an exact catalog pattern hit
// plus a publisher check is required, and ambiguity results in UNMAPPED.
func (c *Catalog) Resolve(in SoftwareInput) Resolution {
	r := c.resolve(in)
	if !r.Mapped {
		r.Kind = UnmappedKind(in)
	}
	return r
}

var componentRe = regexp.MustCompile(`(?i)(\bsdk\b|software development kit|redistributable|\bredist\b|\bruntime\b|runtimes|language pack|proofing|\bfonts?\b|\bdrivers?\b|\badd-?on\b|extension pack|targeting pack|\bheaders\b|\btemplates?\b|\bbootstrapper\b|\bprerequisites?\b|service pack|update for |\bhotfix\b|\bwebview2\b|^vs_|^microsoft\.(vclibs|ui\.xaml|net\.native|windowsappruntime|services\.store)|^windows sdk\b|^windows subsystem for linux update)`)

// UnmappedKind sorts an UNMAPPED record into "component" or "product" with
// documented, conservative rules (name patterns; built-in Microsoft Store packages).
func UnmappedKind(in SoftwareInput) string {
	name := NormalizeName(in.Name)
	if componentRe.MatchString(name) {
		return "component"
	}
	if isStorePackage(in.Source) && strings.EqualFold(strings.TrimSpace(in.Publisher), "Microsoft Corporation") {
		return "component"
	}
	return "product"
}

func (c *Catalog) resolve(in SoftwareInput) Resolution {
	name := NormalizeName(in.Name)
	pub := NormalizeName(in.Publisher)
	if name == "" {
		return Resolution{Reason: "no display name"}
	}
	var hits []*CatalogEntry
	for _, e := range c.Entries {
		if matchAny(e.names, name) && !matchAny(e.exclude, name) {
			hits = append(hits, e)
		}
	}
	if len(hits) == 0 {
		return Resolution{Reason: "product is not in OCULI's verified identity catalog", CatalogMiss: true}
	}
	if len(hits) > 1 {
		ids := make([]string, len(hits))
		for i, h := range hits {
			ids[i] = h.ID
		}
		return Resolution{Reason: "ambiguous: name matches several catalog products (" + strings.Join(ids, ", ") + ")"}
	}
	e := hits[0]
	// Microsoft Store / MSIX packages carry a package version, which is not the
	// product version (e.g. WinRAR.ShellExtension 1.0.0.2 is WinRAR's context-menu
	// package, not WinRAR 1.0). Found on a real Windows endpoint in 0.4.9.8 TEST r1.
	if isStorePackage(in.Source) && !e.AllowStorePackage {
		return Resolution{Reason: "Microsoft Store/MSIX package " + quote(in.Name) + ": its package version is not the " + e.Name + " product version, so it is not mapped (the product's own installation is assessed separately)"}
	}
	id := &Identity{SoftwareID: in.ID, CatalogID: e.ID, Product: e.Name, CPEs: append([]CPERef(nil), e.CPEs...), Scheme: SchemeDotted,
		Arch: in.Arch, Supported: e.Applicability != "unsupported", UnsupportedReason: e.UnsupportedReason, IgnoreSwEdition: e.IgnoreSwEdition,
		CNA: e.CNA, CNATrust: e.CNATrust, Ambiguous: e.CPEMode == "ambiguous"}
	if id.CNATrust == "" {
		id.CNATrust = "fallback"
	}
	switch e.Scheme {
	case "", SchemeDotted:
	case SchemeOpenSSL:
		id.Scheme = SchemeOpenSSL
	default:
		return Resolution{Reason: "catalog entry " + quote(e.ID) + " has unknown version scheme " + quote(e.Scheme)}
	}
	id.Evidence = append(id.Evidence, "Display name "+quote(in.Name)+" matches catalog entry "+quote(e.Name))
	switch {
	case pub == "":
		id.Confidence = "medium"
		id.Evidence = append(id.Evidence, "Publisher missing in inventory; vendor identity not confirmed")
	case matchAny(e.publishers, pub):
		id.Confidence = "high"
		id.Evidence = append(id.Evidence, "Publisher "+quote(in.Publisher)+" confirms the vendor")
	default:
		return Resolution{Reason: "publisher " + quote(in.Publisher) + " does not match the expected vendor for " + e.Name + " (possible look-alike or repackaged software)"}
	}
	// Version extraction
	src := strings.TrimSpace(in.Version)
	id.VersionSource = "registry DisplayVersion"
	if e.VersionFrom == "name" {
		src = strings.TrimSpace(in.Name)
		id.VersionSource = "display name"
	}
	if e.versionRe != nil {
		if m := e.versionRe.FindStringSubmatch(src); len(m) > 1 {
			src = m[1]
		} else {
			src = ""
		}
	}
	if _, ok := ParseVersion(src); ok {
		id.Version = src
		id.Evidence = append(id.Evidence, "Version "+src+" read from "+id.VersionSource)
	} else if strings.TrimSpace(src) != "" {
		id.Evidence = append(id.Evidence, "Version "+quote(src)+" from "+id.VersionSource+" cannot be interpreted")
	} else {
		id.Evidence = append(id.Evidence, "No version available from "+id.VersionSource)
	}
	// Edition
	id.SwEdition = e.SwEdition
	if e.SwEditionFromVersion == "adobe-track" && id.Version != "" {
		id.SwEdition = adobeTrack(id.Version)
		if id.SwEdition != "" {
			id.Evidence = append(id.Evidence, "Adobe "+id.SwEdition+" track derived from version "+id.Version)
			// Only CPEs of the derived track apply.
			var keep []CPERef
			for _, r := range id.CPEs {
				if r.SwEdition == "" || r.SwEdition == id.SwEdition {
					keep = append(keep, r)
				}
			}
			id.CPEs = keep
		}
	}
	return Resolution{Mapped: true, Identity: id}
}

func matchAny(res []*regexp.Regexp, s string) bool {
	for _, r := range res {
		if r.MatchString(s) {
			return true
		}
	}
	return false
}

// adobeTrack: Acrobat Continuous builds use a 2xxxx third segment, Classic 3xxxx.
func adobeTrack(v string) string {
	p := strings.Split(v, ".")
	if len(p) < 3 || len(p[2]) < 5 {
		return ""
	}
	switch p[2][0] {
	case '2':
		return "continuous"
	case '3':
		return "classic"
	}
	return ""
}

// --- Windows OS identity ---

type windowsRelease struct {
	build      int
	server     bool
	cpeProduct string
	label      string
	msrc       []string // Microsoft CNA product names (lower-case, before platform suffixes)
}

// Build → product. Sources: Microsoft release information; CPE names verified
// against NVD records (e.g. CVE-2024-38063, CVE-2024-43451).
var windowsTable = []windowsRelease{
	{10240, false, "windows_10_1507", "Windows 10 1507", []string{"windows 10 version 1507"}},
	{14393, false, "windows_10_1607", "Windows 10 1607", []string{"windows 10 version 1607"}},
	{17763, false, "windows_10_1809", "Windows 10 1809", []string{"windows 10 version 1809"}},
	{19044, false, "windows_10_21h2", "Windows 10 21H2", []string{"windows 10 version 21h2"}},
	{19045, false, "windows_10_22h2", "Windows 10 22H2", []string{"windows 10 version 22h2"}},
	{22000, false, "windows_11_21h2", "Windows 11 21H2", []string{"windows 11 version 21h2"}},
	{22621, false, "windows_11_22h2", "Windows 11 22H2", []string{"windows 11 version 22h2"}},
	{22631, false, "windows_11_23h2", "Windows 11 23H2", []string{"windows 11 version 23h2", "windows 11 version 22h3"}},
	{26100, false, "windows_11_24h2", "Windows 11 24H2", []string{"windows 11 version 24h2"}},
	{26200, false, "windows_11_25h2", "Windows 11 25H2", []string{"windows 11 version 25h2"}},
	{26300, false, "windows_11_26h2", "Windows 11 26H2", []string{"windows 11 version 26h2"}}, // verified: CVE-2026-96951 (NVD + MSRC), real endpoint r6
	{28000, false, "windows_11_26h1", "Windows 11 26H1", []string{"windows 11 version 26h1"}}, // verified: CVE-2026-21510, CVE-2026-32202
	{14393, true, "windows_server_2016", "Windows Server 2016", []string{"windows server 2016"}},
	{17763, true, "windows_server_2019", "Windows Server 2019", []string{"windows server 2019"}},
	{20348, true, "windows_server_2022", "Windows Server 2022", []string{"windows server 2022"}},
	{25398, true, "windows_server_2022_23h2", "Windows Server 2022 23H2", []string{"windows server 2022, 23h2 edition"}},
	{26100, true, "windows_server_2025", "Windows Server 2025", []string{"windows server 2025"}},
}

// OSInput is the OS evidence from the inventory.
type OSInput struct {
	Name             string // e.g. "Windows 11 Pro"
	DisplayVersion   string // e.g. "24H2"
	Build            string // e.g. "26100.2314" (CurrentBuild.UBR)
	Arch             string // e.g. "X64"
	InstallationType string // Client, Server, Server Core
}

// ResolveWindows maps the OS to a CPE identity with version 10.0.<build>.<UBR>.
func ResolveWindows(in OSInput) Resolution {
	parts := strings.Split(strings.TrimSpace(in.Build), ".")
	if len(parts) != 2 {
		return Resolution{Reason: "OS build " + quote(in.Build) + " is not in <build>.<UBR> form"}
	}
	build, e1 := strconv.Atoi(parts[0])
	ubr, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || build <= 0 || ubr < 0 {
		return Resolution{Reason: "OS build " + quote(in.Build) + " cannot be interpreted"}
	}
	server := strings.Contains(strings.ToLower(in.Name), "server") || strings.HasPrefix(strings.ToLower(in.InstallationType), "server")
	var rel *windowsRelease
	for i := range windowsTable {
		if windowsTable[i].build == build && windowsTable[i].server == server {
			rel = &windowsTable[i]
			break
		}
	}
	if rel == nil {
		kind := "Windows client"
		if server {
			kind = "Windows Server"
		}
		return Resolution{Reason: fmt.Sprintf("%s build %d is not in OCULI's Windows release table (possibly an Insider/preview or unsupported release); OS CVEs cannot be evaluated", kind, build)}
	}
	arch := normArch(in.Arch)
	id := &Identity{SoftwareID: "os-windows", CatalogID: "windows-os", Product: rel.label, CPEs: []CPERef{{Part: "o", Vendor: "microsoft", Product: rel.cpeProduct}},
		Version: fmt.Sprintf("10.0.%d.%d", build, ubr), VersionSource: "registry CurrentBuild + UBR", Scheme: SchemeWindows, Arch: arch,
		Confidence: "high", Supported: true, IsOS: true, OSFamily: "windows", CNATrust: "primary"}
	for _, n := range rel.msrc {
		id.CNA = append(id.CNA, VendorProduct{Vendor: "microsoft", Product: n})
		if strings.HasPrefix(strings.ToLower(in.InstallationType), "server core") {
			id.CNA = append(id.CNA, VendorProduct{Vendor: "microsoft", Product: n + " (server core installation)"})
		}
	}
	switch arch {
	case "x64":
		id.CNAPlatforms = []string{"x64-based systems"}
	case "x86":
		id.CNAPlatforms = []string{"32-bit systems"}
	case "arm64":
		id.CNAPlatforms = []string{"arm64-based systems"}
	}
	id.Evidence = []string{
		fmt.Sprintf("OS %q, build %d.%d → %s (cpe:2.3:o:microsoft:%s)", in.Name, build, ubr, rel.label, rel.cpeProduct),
		"Patch level evaluated from build revision (UBR); cumulative updates raise the UBR",
	}
	if in.DisplayVersion != "" {
		id.Evidence = append(id.Evidence, "Registry DisplayVersion "+quote(in.DisplayVersion)+" (identity is taken from the build number)")
	}
	if arch == "" {
		id.Evidence = append(id.Evidence, "OS architecture unknown; architecture-specific advisories evaluate as unknown")
	}
	return Resolution{Mapped: true, Identity: id}
}

func normArch(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "x64", "amd64", "x86_64", "64-bit":
		return "x64"
	case "x86", "i386", "i686", "32-bit":
		return "x86"
	case "arm64", "aarch64":
		return "arm64"
	}
	return ""
}

func isStorePackage(source string) bool {
	for _, part := range strings.Split(source, "+") {
		if strings.EqualFold(strings.TrimSpace(part), "AppX") {
			return true
		}
	}
	return false
}

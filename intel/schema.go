package intel

// SchemaVersion is the snapshot payload/manifest schema understood by this build.
// A snapshot with a different schema is refused (never partially interpreted).
const SchemaVersion = 1

// Manifest describes a signed snapshot. The signature covers the JSON encoding
// of the manifest with Signature set to "". PayloadSHA256 binds the payload.
type Manifest struct {
	Schema         int          `json:"schema"`
	SnapshotID     string       `json:"snapshotId"`
	Created        string       `json:"created"`
	Builder        string       `json:"builder"`
	Test           bool         `json:"test"`
	CatalogVersion string       `json:"catalogVersion"`
	PayloadFile    string       `json:"payloadFile"`
	PayloadSHA256  string       `json:"payloadSha256"`
	PayloadSize    int64        `json:"payloadSize"`
	CVECount       int          `json:"cveCount"`
	Coverage       []Coverage   `json:"coverage"`
	Sources        []SourceInfo `json:"sources"`
	Notes          []string     `json:"notes,omitempty"`
	// FullFeed: built from the complete NVD feed (every CPE covered), not a per-product query or sample.
	FullFeed  bool   `json:"fullFeed,omitempty"`
	KeyID     string `json:"keyId"`
	Signature string `json:"signature"`
}

// Coverage states, per catalog CPE identity, how completely it was collected.
type Coverage struct {
	CPE      string `json:"cpe"`      // part:vendor:product
	Method   string `json:"method"`   // "nvd-virtualMatchString" (complete) or "sample-ids"
	Complete bool   `json:"complete"` // true only when the full NVD product query succeeded
	CVEs     int    `json:"cves"`
}

// SourceInfo records provenance for every intelligence source used.
type SourceInfo struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Retrieved string `json:"retrieved"`
	Version   string `json:"version,omitempty"`
	Records   int    `json:"records"`
	Terms     string `json:"terms"`
	Note      string `json:"note,omitempty"`
}

// Payload is the decompressed snapshot body.
type Payload struct {
	Schema int   `json:"schema"`
	CVEs   []CVE `json:"cves"`
}

// CVE is the normalized, source-attributed record OCULI evaluates.
type CVE struct {
	ID          string `json:"id"`
	State       string `json:"state"`     // CVE Program state: PUBLISHED / REJECTED
	NVDStatus   string `json:"nvdStatus"` // Analyzed, Modified, Deferred, Rejected, ...
	Published   string `json:"published,omitempty"`
	Modified    string `json:"modified,omitempty"`
	Description string `json:"description,omitempty"`
	Disputed    bool   `json:"disputed,omitempty"`

	CVSS       []CVSS      `json:"cvss,omitempty"`
	KEV        *KEVInfo    `json:"kev,omitempty"`
	EPSS       *EPSSInfo   `json:"epss,omitempty"`
	SSVC       string      `json:"ssvcExploitation,omitempty"` // CISA ADP SSVC "Exploitation": none / poc / active
	References []Reference `json:"references,omitempty"`

	NVD []Config   `json:"nvd,omitempty"` // NVD configurations (CPE applicability)
	ADP []RangeSet `json:"adp,omitempty"` // CISA ADP (Vulnrichment) affected data with CPEs
	CNA []RangeSet `json:"cna,omitempty"` // CNA affected data (free-text vendor/product)

	Sources []string `json:"sources"` // which sources contributed: nvd, cve.org, kev, epss
}

// CVSS keeps each metric with its provenance; OCULI never merges them into one invented score.
type CVSS struct {
	Version  string  `json:"version"`
	Source   string  `json:"source"`
	Type     string  `json:"type,omitempty"` // Primary / Secondary (NVD), or "adp"/"cna"
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Vector   string  `json:"vector,omitempty"`
}

type KEVInfo struct {
	DateAdded  string `json:"dateAdded"`
	DueDate    string `json:"dueDate,omitempty"`
	Action     string `json:"requiredAction,omitempty"`
	Ransomware string `json:"knownRansomwareCampaignUse,omitempty"`
	Name       string `json:"name,omitempty"`
}

type EPSSInfo struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

type Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags,omitempty"`
}

// Config is one NVD configuration: Nodes combined by Operator (AND/OR), optionally negated.
type Config struct {
	Operator string `json:"op,omitempty"`
	Negate   bool   `json:"neg,omitempty"`
	Nodes    []Node `json:"nodes"`
}

// Node combines CPE match criteria with Operator.
type Node struct {
	Operator string  `json:"op,omitempty"`
	Negate   bool    `json:"neg,omitempty"`
	Matches  []Match `json:"m"`
}

// Match is one NVD cpeMatch criterion.
type Match struct {
	Vulnerable bool   `json:"v"`
	CPE        string `json:"cpe"`
	VSI        string `json:"vsi,omitempty"` // versionStartIncluding
	VSE        string `json:"vse,omitempty"` // versionStartExcluding
	VEI        string `json:"vei,omitempty"` // versionEndIncluding
	VEE        string `json:"vee,omitempty"` // versionEndExcluding

	parsed *CPE // filled once when the snapshot is indexed
}

// parsedCPE returns the criterion's CPE, parsing it only if it was not pre-parsed.
func (m *Match) parsedCPE() (CPE, error) {
	if m.parsed != nil {
		return *m.parsed, nil
	}
	return ParseCPE(m.CPE)
}

// RangeSet is a CVE 5.x "affected" product entry (from the CNA or CISA ADP container).
type RangeSet struct {
	Vendor        string         `json:"vendor"`
	Product       string         `json:"product"`
	CPEs          []string       `json:"cpes,omitempty"`
	DefaultStatus string         `json:"defaultStatus,omitempty"`
	Platforms     []string       `json:"platforms,omitempty"`
	Versions      []VersionEntry `json:"versions,omitempty"`
}

type VersionEntry struct {
	Version         string `json:"version"`
	Status          string `json:"status"`
	LessThan        string `json:"lessThan,omitempty"`
	LessThanOrEqual string `json:"lessThanOrEqual,omitempty"`
	VersionType     string `json:"versionType,omitempty"`
	HasChanges      bool   `json:"changes,omitempty"`
}

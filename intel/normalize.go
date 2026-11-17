package intel

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var cveIDRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// ValidCVEID reports whether s is a syntactically valid CVE ID.
func ValidCVEID(s string) bool { return cveIDRe.MatchString(s) }

const maxDescription = 700

// --- NVD CVE API 2.0 ("cve" object, as returned inside vulnerabilities[].cve) ---

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	CisaAdded    string `json:"cisaExploitAdd"`
	CisaDue      string `json:"cisaActionDue"`
	CisaAction   string `json:"cisaRequiredAction"`
	CisaName     string `json:"cisaVulnerabilityName"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]struct {
		Source   string          `json:"source"`
		Type     string          `json:"type"`
		CvssData json.RawMessage `json:"cvssData"`
		Severity string          `json:"baseSeverity"` // v2 keeps severity outside cvssData
	} `json:"metrics"`
	Configurations []struct {
		Operator string `json:"operator"`
		Negate   bool   `json:"negate"`
		Nodes    []struct {
			Operator string `json:"operator"`
			Negate   bool   `json:"negate"`
			CPEMatch []struct {
				Vulnerable bool   `json:"vulnerable"`
				Criteria   string `json:"criteria"`
				VSI        string `json:"versionStartIncluding"`
				VSE        string `json:"versionStartExcluding"`
				VEI        string `json:"versionEndIncluding"`
				VEE        string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
}

// FromNVD normalizes one NVD API 2.0 cve object. Malformed CPE criteria are
// dropped and reported; a record with no valid ID is rejected.
func FromNVD(raw []byte) (CVE, []string, error) {
	var n nvdCVE
	if err := json.Unmarshal(raw, &n); err != nil {
		return CVE{}, nil, fmt.Errorf("invalid NVD record: %w", err)
	}
	if !ValidCVEID(n.ID) {
		return CVE{}, nil, fmt.Errorf("invalid NVD record ID %q", n.ID)
	}
	var warnings []string
	c := CVE{ID: n.ID, NVDStatus: n.VulnStatus, Published: n.Published, Modified: n.LastModified, State: "PUBLISHED", Sources: []string{"nvd"}}
	if strings.EqualFold(n.VulnStatus, "Rejected") {
		c.State = "REJECTED"
	}
	for _, d := range n.Descriptions {
		if d.Lang == "en" {
			c.Description = truncate(d.Value, maxDescription)
			break
		}
	}
	// Metrics: keep each with provenance.
	keys := make([]string, 0, len(n.Metrics))
	for k := range n.Metrics {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, m := range n.Metrics[k] {
			var d struct {
				Version  string  `json:"version"`
				Score    float64 `json:"baseScore"`
				Severity string  `json:"baseSeverity"`
				Vector   string  `json:"vectorString"`
			}
			if json.Unmarshal(m.CvssData, &d) != nil || d.Score < 0 || d.Score > 10 {
				continue
			}
			sev := d.Severity
			if sev == "" {
				sev = m.Severity
			}
			c.CVSS = append(c.CVSS, CVSS{Version: d.Version, Source: m.Source, Type: m.Type, Score: d.Score, Severity: strings.ToUpper(sev), Vector: d.Vector})
		}
	}
	if n.CisaAdded != "" {
		c.KEV = &KEVInfo{DateAdded: n.CisaAdded, DueDate: n.CisaDue, Action: n.CisaAction, Name: n.CisaName}
	}
	for _, cfg := range n.Configurations {
		out := Config{Operator: strings.ToUpper(cfg.Operator), Negate: cfg.Negate}
		for _, node := range cfg.Nodes {
			nn := Node{Operator: strings.ToUpper(node.Operator), Negate: node.Negate}
			for _, m := range node.CPEMatch {
				if _, err := ParseCPE(m.Criteria); err != nil {
					warnings = append(warnings, n.ID+": dropped criteria "+truncate(m.Criteria, 120)+": "+err.Error())
					continue
				}
				nn.Matches = append(nn.Matches, Match{Vulnerable: m.Vulnerable, CPE: m.Criteria, VSI: m.VSI, VSE: m.VSE, VEI: m.VEI, VEE: m.VEE})
			}
			if len(nn.Matches) > 0 {
				out.Nodes = append(out.Nodes, nn)
			}
		}
		if len(out.Nodes) > 0 {
			c.NVD = append(c.NVD, out)
		}
	}
	for _, r := range n.References {
		if len(c.References) >= 40 {
			break
		}
		if strings.HasPrefix(r.URL, "https://") || strings.HasPrefix(r.URL, "http://") {
			c.References = append(c.References, Reference{URL: truncate(r.URL, 400), Tags: r.Tags})
		}
	}
	return c, warnings, nil
}

// --- CVE JSON 5.x record (CVE Program / cvelistV5 / CVE Services) ---

type cve5Affected struct {
	Vendor        string   `json:"vendor"`
	Product       string   `json:"product"`
	CPEs          []string `json:"cpes"`
	DefaultStatus string   `json:"defaultStatus"`
	Platforms     []string `json:"platforms"`
	Versions      []struct {
		Version         string            `json:"version"`
		Status          string            `json:"status"`
		LessThan        string            `json:"lessThan"`
		LessThanOrEqual string            `json:"lessThanOrEqual"`
		VersionType     string            `json:"versionType"`
		Changes         []json.RawMessage `json:"changes"`
	} `json:"versions"`
}

type cve5Record struct {
	Meta struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
		Updated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Tags         []string `json:"tags"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Affected   []cve5Affected `json:"affected"`
			References []struct {
				URL  string   `json:"url"`
				Tags []string `json:"tags"`
			} `json:"references"`
		} `json:"cna"`
		ADP []struct {
			Title    string `json:"title"`
			Provider struct {
				Short string `json:"shortName"`
			} `json:"providerMetadata"`
			Affected []cve5Affected               `json:"affected"`
			Metrics  []map[string]json.RawMessage `json:"metrics"`
		} `json:"adp"`
	} `json:"containers"`
}

// MergeCVE5 adds CVE Program data (state, disputed tag, CNA and CISA ADP affected
// data, SSVC exploitation) to c. If c is empty, it is initialized from the record.
func MergeCVE5(c *CVE, raw []byte) error {
	var r cve5Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("invalid CVE record: %w", err)
	}
	if !ValidCVEID(r.Meta.ID) {
		return fmt.Errorf("invalid CVE record ID %q", r.Meta.ID)
	}
	if c.ID == "" {
		c.ID = r.Meta.ID
		c.Published = r.Meta.Published
		c.Modified = r.Meta.Updated
	}
	if c.ID != r.Meta.ID {
		return fmt.Errorf("CVE record ID mismatch: %s vs %s", c.ID, r.Meta.ID)
	}
	state := strings.ToUpper(r.Meta.State)
	if state == "REJECTED" || c.State == "" {
		c.State = state
	}
	for _, t := range r.Containers.CNA.Tags {
		if strings.EqualFold(t, "disputed") {
			c.Disputed = true
		}
	}
	if c.Description == "" {
		for _, d := range r.Containers.CNA.Descriptions {
			if strings.HasPrefix(d.Lang, "en") {
				c.Description = truncate(d.Value, maxDescription)
				break
			}
		}
	}
	c.CNA = nil
	for _, a := range r.Containers.CNA.Affected {
		if rs, ok := toRangeSet(a, false); ok {
			c.CNA = append(c.CNA, rs)
		}
	}
	c.ADP = nil
	for _, adp := range r.Containers.ADP {
		name := adp.Provider.Short
		if !strings.EqualFold(name, "CISA-ADP") && !strings.Contains(strings.ToLower(adp.Title), "cisa") {
			continue // only CISA ADP enrichment is used; other ADP containers are ignored
		}
		for _, a := range adp.Affected {
			if rs, ok := toRangeSet(a, true); ok {
				c.ADP = append(c.ADP, rs)
			}
		}
		for _, m := range adp.Metrics {
			if v, ok := m["cvssV3_1"]; ok {
				var d struct {
					Version  string  `json:"version"`
					Score    float64 `json:"baseScore"`
					Severity string  `json:"baseSeverity"`
					Vector   string  `json:"vectorString"`
				}
				if json.Unmarshal(v, &d) == nil && d.Score >= 0 && d.Score <= 10 && !hasCVSS(c, d.Vector) {
					c.CVSS = append(c.CVSS, CVSS{Version: d.Version, Source: "CISA ADP", Type: "adp", Score: d.Score, Severity: strings.ToUpper(d.Severity), Vector: d.Vector})
				}
			}
			if v, ok := m["other"]; ok {
				var o struct {
					Type    string `json:"type"`
					Content struct {
						Options []map[string]string `json:"options"`
					} `json:"content"`
				}
				if json.Unmarshal(v, &o) == nil && strings.EqualFold(o.Type, "ssvc") {
					for _, opt := range o.Content.Options {
						if e, ok := opt["Exploitation"]; ok {
							c.SSVC = strings.ToLower(e)
						}
					}
				}
			}
		}
	}
	if len(c.References) == 0 {
		for _, ref := range r.Containers.CNA.References {
			if len(c.References) >= 40 {
				break
			}
			if strings.HasPrefix(ref.URL, "https://") || strings.HasPrefix(ref.URL, "http://") {
				c.References = append(c.References, Reference{URL: truncate(ref.URL, 400), Tags: ref.Tags})
			}
		}
	}
	addSource(c, "cve.org")
	return nil
}

func toRangeSet(a cve5Affected, requireCPE bool) (RangeSet, bool) {
	rs := RangeSet{Vendor: truncate(a.Vendor, 120), Product: truncate(a.Product, 160), DefaultStatus: strings.ToLower(a.DefaultStatus), Platforms: a.Platforms}
	for _, c := range a.CPEs {
		if _, err := ParseCPE(c); err == nil {
			rs.CPEs = append(rs.CPEs, c)
		}
	}
	if requireCPE && len(rs.CPEs) == 0 {
		return rs, false
	}
	for _, v := range a.Versions {
		if len(rs.Versions) >= 60 {
			break
		}
		rs.Versions = append(rs.Versions, VersionEntry{Version: truncate(v.Version, 80), Status: strings.ToLower(v.Status), LessThan: truncate(v.LessThan, 80),
			LessThanOrEqual: truncate(v.LessThanOrEqual, 80), VersionType: strings.ToLower(v.VersionType), HasChanges: len(v.Changes) > 0})
	}
	return rs, rs.Vendor != "" || len(rs.CPEs) > 0
}

func hasCVSS(c *CVE, vector string) bool {
	for _, x := range c.CVSS {
		if x.Vector == vector && vector != "" {
			return true
		}
	}
	return false
}

// --- CISA KEV ---

// KEVRecord is one row of the CISA KEV JSON catalog.
type KEVRecord struct {
	CVE        string `json:"cveID"`
	Vendor     string `json:"vendorProject"`
	Product    string `json:"product"`
	Name       string `json:"vulnerabilityName"`
	DateAdded  string `json:"dateAdded"`
	DueDate    string `json:"dueDate"`
	Action     string `json:"requiredAction"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

type KEVCatalog struct {
	Version  string      `json:"catalogVersion"`
	Released string      `json:"dateReleased"`
	Count    int         `json:"count"`
	Items    []KEVRecord `json:"vulnerabilities"`
}

// ParseKEV validates the CISA KEV catalog structure.
func ParseKEV(raw []byte) (KEVCatalog, error) {
	var k KEVCatalog
	if err := json.Unmarshal(raw, &k); err != nil {
		return k, fmt.Errorf("invalid KEV catalog: %w", err)
	}
	if k.Version == "" || len(k.Items) < 100 || len(k.Items) > 50000 {
		return k, fmt.Errorf("unexpected KEV catalog shape")
	}
	for _, r := range k.Items {
		if !ValidCVEID(r.CVE) {
			return k, fmt.Errorf("invalid KEV CVE ID %q", r.CVE)
		}
	}
	return k, nil
}

// ApplyKEV sets KEV info on c from a KEV row.
func ApplyKEV(c *CVE, r KEVRecord) {
	c.KEV = &KEVInfo{DateAdded: r.DateAdded, DueDate: r.DueDate, Action: truncate(r.Action, 400), Ransomware: r.Ransomware, Name: truncate(r.Name, 200)}
	addSource(c, "cisa-kev")
}

// --- FIRST EPSS API v1 (https://api.first.org/data/v1/epss) ---

// ParseEPSS parses the documented EPSS API response {"data":[{"cve","epss","percentile","date"}]}.
func ParseEPSS(raw []byte) (map[string]EPSSInfo, error) {
	var r struct {
		Status string `json:"status"`
		Data   []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("invalid EPSS response: %w", err)
	}
	out := map[string]EPSSInfo{}
	for _, d := range r.Data {
		e, err1 := strconv.ParseFloat(d.EPSS, 64)
		p, err2 := strconv.ParseFloat(d.Percentile, 64)
		if !ValidCVEID(d.CVE) || err1 != nil || err2 != nil || e < 0 || e > 1 || p < 0 || p > 1 {
			continue
		}
		out[d.CVE] = EPSSInfo{Score: e, Percentile: p, Date: d.Date}
	}
	return out, nil
}

func addSource(c *CVE, s string) {
	for _, x := range c.Sources {
		if x == s {
			return
		}
	}
	c.Sources = append(c.Sources, s)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	// avoid cutting inside a UTF-8 sequence
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n] + "…"
}

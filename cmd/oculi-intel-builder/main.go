// oculi-intel-builder builds, signs and verifies OCULI vulnerability-intelligence
// snapshots. It is the prototype of the central intelligence service: endpoints
// never query NVD themselves; they receive a validated, signed snapshot.
//
//	oculi-intel-builder keygen -out keys -id oculi-test-2026
//	oculi-intel-builder build  -out snap -key keys/oculi-test-2026.key [-mode nvd-api|ids] ...
//	oculi-intel-builder verify -dir snap -pub keys/oculi-test-2026.pub
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sentri/intel"
)

const userAgent = "OCULI-Intel-Builder/0.4.9.8-TEST"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "build":
		err = build(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: oculi-intel-builder keygen|build|verify [flags]  (use -h after a command)")
	os.Exit(2)
}

// ---------------- keys ----------------

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "keys", "output directory")
	id := fs.String("id", "", "key ID, e.g. oculi-test-2026")
	fs.Parse(args)
	if *id == "" {
		return errors.New("-id is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	privPath := filepath.Join(*out, *id+".key")
	if _, err := os.Stat(privPath); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite a signing key", privPath)
	}
	line := *id + ":" + base64.StdEncoding.EncodeToString(pub)
	if _, _, err := intel.ParsePublicKey(line); err != nil {
		return err
	}
	if err := os.WriteFile(privPath, []byte(*id+":"+base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, *id+".pub"), []byte(line+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Println("public key:", line)
	fmt.Println("private key written to", privPath, "- keep it offline; it is NOT part of the source tree")
	return nil
}

func loadPrivate(path string) (string, ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	id, b64, ok := strings.Cut(strings.TrimSpace(string(b)), ":")
	if !ok {
		return "", nil, errors.New("private key file must be keyid:base64")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return "", nil, errors.New("invalid private key")
	}
	return id, ed25519.PrivateKey(raw), nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("dir", "", "snapshot directory")
	pubPath := fs.String("pub", "", "public key file (keyid:base64)")
	fs.Parse(args)
	b, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	id, pub, err := intel.ParsePublicKey(string(b))
	if err != nil {
		return err
	}
	s, err := intel.ReadSnapshotFS(os.DirFS(*dir), intel.TrustedKeys{id: pub})
	if err != nil {
		return err
	}
	fmt.Printf("OK: snapshot %s, %d CVEs, created %s, test=%v, key %s\n", s.Manifest.SnapshotID, s.Len(), s.Manifest.Created, s.Manifest.Test, s.Manifest.KeyID)
	return nil
}

// ---------------- build ----------------

type cfg struct {
	out, keyPath, mode, idsFile, nvdAPI, nvdRecordURL, cve5URL, cve5Policy, kevSrc, epssURL, nvdFeed string
	test, kevSeed                                                                                    bool
	nvdKey                                                                                           string
	maxPerCPE, workers                                                                               int
	nvdGap                                                                                           time.Duration
}

func build(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	var c cfg
	fs.StringVar(&c.out, "out", "", "output directory (must not exist)")
	fs.StringVar(&c.keyPath, "key", "", "private signing key file")
	fs.StringVar(&c.mode, "mode", "nvd-api", "nvd-api: complete per-CPE NVD query; nvd-feed: every relevant CVE from a complete NVD 2.0 JSON feed file (-nvd-feed); ids: only the CVE IDs in -ids (sample coverage)")
	fs.StringVar(&c.nvdFeed, "nvd-feed", "", "complete NVD API 2.0 feed file for -mode nvd-feed (JSON or .json.gz, e.g. fkie-cad CVE-all.json)")
	fs.StringVar(&c.idsFile, "ids", "", "file with CVE IDs (one per line) for -mode ids; also merged in nvd-api mode")
	fs.StringVar(&c.nvdAPI, "nvd-api", "https://services.nvd.nist.gov/rest/json/cves/2.0", "NVD CVE API 2.0 endpoint")
	fs.StringVar(&c.nvdRecordURL, "nvd-record-url", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}", "per-CVE NVD record URL template ({id},{year},{nvdbucket})")
	fs.StringVar(&c.cve5URL, "cve5-url", "https://cveawg.mitre.org/api/cve/{id}", "per-CVE CVE JSON 5 record URL template ({id},{year},{cve5bucket})")
	fs.StringVar(&c.cve5Policy, "cve5", "trusted", "which CVEs get CVE Program records: all, trusted (products whose vendor CNA data is used), missing (no NVD configuration), none")
	fs.StringVar(&c.kevSrc, "kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "CISA KEV catalog URL or file")
	fs.BoolVar(&c.kevSeed, "kev-seed", true, "also include KEV CVEs for catalog vendors (covers CVEs NVD has not analysed yet)")
	fs.StringVar(&c.epssURL, "epss", "https://api.first.org/data/v1/epss", "FIRST EPSS API endpoint, or 'off'")
	fs.BoolVar(&c.test, "test", false, "mark the snapshot as TEST")
	fs.IntVar(&c.maxPerCPE, "max-per-cpe", 20000, "safety cap on CVEs per CPE")
	fs.IntVar(&c.workers, "workers", 4, "parallel per-record fetches")
	fs.DurationVar(&c.nvdGap, "nvd-gap", 0, "delay between NVD API pages (default: 6.5s without NVD_API_KEY, 0.7s with)")
	fs.Parse(args)
	c.nvdKey = os.Getenv("NVD_API_KEY")
	if c.out == "" || c.keyPath == "" {
		return errors.New("-out and -key are required")
	}
	keyID, priv, err := loadPrivate(c.keyPath)
	if err != nil {
		return err
	}
	cat, err := intel.DefaultCatalog()
	if err != nil {
		return err
	}
	b := &builder{c: c, cat: cat, http: &http.Client{Timeout: 60 * time.Second}, cves: map[string]*intel.CVE{}}
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	man := intel.Manifest{SnapshotID: "oculi-intel-" + time.Now().UTC().Format("20060102T150405Z"), Created: now, Builder: userAgent, Test: c.test, CatalogVersion: cat.Version}

	// 1. KEV (needed for seeding and flags)
	kev, kevInfo := b.loadKEV(ctx)
	man.Sources = append(man.Sources, kevInfo)

	// 2. Candidate CVE IDs
	extra := map[string]bool{}
	if c.idsFile != "" {
		ids, err := readIDs(c.idsFile)
		if err != nil {
			return err
		}
		for _, id := range ids {
			extra[id] = true
		}
	}
	if c.kevSeed {
		for _, r := range kev.Items {
			if kevVendorRelevant(r) {
				extra[r.CVE] = true
			}
		}
	}
	coverage := map[string]*intel.Coverage{}
	for _, k := range cat.AllCPEKeys() {
		coverage[k] = &intel.Coverage{CPE: k, Method: "sample-ids"}
	}
	nvdInfo := intel.SourceInfo{Name: "NVD CVE API 2.0", Retrieved: now, Terms: "NVD data is public; this product uses the NVD API but is not endorsed or certified by the NVD."}
	if c.mode == "nvd-api" {
		nvdInfo.URL = c.nvdAPI
		for _, k := range cat.AllCPEKeys() {
			n, err := b.nvdByCPE(ctx, k)
			cv := coverage[k]
			cv.Method = "nvd-virtualMatchString"
			if err != nil {
				fmt.Fprintf(os.Stderr, "NVD query for %s failed: %v (coverage marked incomplete)\n", k, err)
				man.Notes = append(man.Notes, "NVD query failed for "+k+": "+err.Error())
				continue
			}
			cv.Complete = true
			fmt.Fprintf(os.Stderr, "NVD %s: %d CVEs\n", k, n)
		}
	} else if c.mode == "nvd-feed" {
		n, ts, trustedNoCfg, err := b.loadFeed(c.nvdFeed)
		if err != nil {
			return err
		}
		nvdInfo.URL = "file:" + filepath.Base(c.nvdFeed)
		nvdInfo.Version = ts
		nvdInfo.Note = fmt.Sprintf("Complete NVD API 2.0 feed (%d records read); all CPEs relevant to Windows endpoints kept", n)
		man.FullFeed = true
		for _, k := range cat.AllCPEKeys() {
			coverage[k].Method, coverage[k].Complete = "nvd-full-feed", true
		}
		man.Notes = append(man.Notes, "Built from the complete NVD feed (timestamp "+ts+"). Every product with an NVD CPE is covered; CVEs NVD has not analysed yet have no CPE data unless a trusted CNA record or KEV supplies it.")
		for _, id := range trustedNoCfg {
			extra[id] = true
		}
	} else if c.mode == "ids" {
		nvdInfo.URL = c.nvdRecordURL
		nvdInfo.Note = "Per-ID retrieval of a sample of CVE IDs; NOT complete coverage"
		man.Notes = append(man.Notes, "Sample snapshot: only listed and KEV-seeded CVE IDs were collected. Products are NOT completely covered.")
	} else {
		return fmt.Errorf("unknown -mode %q", c.mode)
	}
	// Per-ID NVD records for extra IDs not already present.
	var need []string
	for id := range extra {
		if _, ok := b.cves[id]; !ok {
			need = append(need, id)
		}
	}
	sort.Strings(need)
	b.parallel(need, func(id string) {
		raw, err := b.get(ctx, expand(c.nvdRecordURL, id), 4<<20)
		if err != nil {
			b.warn("NVD record %s: %v", id, err)
			return
		}
		b.addNVD(raw, id)
	})
	nvdInfo.Records = len(b.cves)
	man.Sources = append(man.Sources, nvdInfo)

	// 3. CVE Program records (CNA + CISA ADP)
	cve5Info := intel.SourceInfo{Name: "CVE Program (CVE JSON 5 records: CNA and CISA ADP containers)", URL: c.cve5URL, Retrieved: now, Terms: "CVE Program Terms of Use (https://www.cve.org/Legal/TermsOfUse); CVE® is a registered trademark of The MITRE Corporation."}
	var want5 []string
	for _, id := range need {
		if _, ok := b.cves[id]; !ok {
			want5 = append(want5, id) // not in NVD at all: CVE Program record is the only source
		}
	}
	for id, cv := range b.cves {
		if c.cve5Policy == "all" || (c.cve5Policy == "missing" && len(cv.NVD) == 0) || (c.cve5Policy == "trusted" && (len(cv.NVD) == 0 || b.referencesTrustedVendor(cv))) {
			want5 = append(want5, id)
		}
	}
	want5 = dedupe(want5)
	if c.cve5Policy != "none" {
		var mu sync.Mutex
		count := 0
		b.parallel(want5, func(id string) {
			raw, err := b.get(ctx, expand(c.cve5URL, id), 4<<20)
			if err != nil {
				b.warn("CVE record %s: %v", id, err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			cv := b.cves[id]
			if cv == nil {
				cv = &intel.CVE{}
			}
			if err := intel.MergeCVE5(cv, raw); err != nil {
				b.warn("CVE record %s: %v", id, err)
				return
			}
			b.cves[cv.ID] = cv
			count++
		})
		cve5Info.Records = count
	}
	man.Sources = append(man.Sources, cve5Info)

	// 4. Keep only CVEs that reference a catalog identity; apply KEV.
	payload := intel.Payload{}
	kevBy := map[string]intel.KEVRecord{}
	for _, r := range kev.Items {
		kevBy[r.CVE] = r
	}
	for _, cv := range b.cves {
		keys := referencedKeys(cv, cat)
		if len(keys) == 0 && !(c.mode == "nvd-feed" && relevantFull(cv)) {
			continue
		}
		if c.mode == "nvd-feed" {
			slim(cv)
		}
		if r, ok := kevBy[cv.ID]; ok {
			intel.ApplyKEV(cv, r)
		}
		for _, k := range keys {
			if cov := coverage[k]; cov != nil {
				cov.CVEs++
			}
		}
		payload.CVEs = append(payload.CVEs, *cv)
	}

	// 5. EPSS
	epssInfo := intel.SourceInfo{Name: "FIRST EPSS", URL: c.epssURL, Retrieved: now, Terms: "EPSS data © FIRST; free to use with attribution (https://www.first.org/epss/)"}
	if c.epssURL != "off" {
		got, err := b.epss(ctx, payload.CVEs)
		if err != nil {
			epssInfo.Note = "not retrieved: " + err.Error()
			man.Notes = append(man.Notes, "EPSS not included: "+err.Error())
		}
		for i := range payload.CVEs {
			if e, ok := got[payload.CVEs[i].ID]; ok {
				e := e
				payload.CVEs[i].EPSS = &e
				payload.CVEs[i].Sources = append(payload.CVEs[i].Sources, "epss")
				epssInfo.Records++
			}
		}
	} else {
		epssInfo.Note = "disabled"
	}
	man.Sources = append(man.Sources, epssInfo)
	for _, k := range cat.AllCPEKeys() {
		man.Coverage = append(man.Coverage, *coverage[k])
	}
	m, err := intel.WriteSnapshot(c.out, man, payload, keyID, priv)
	if err != nil {
		return err
	}
	bundle, err := intel.MakeBundle(c.out)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.out+".oculi-intel.zip", bundle, 0o600); err != nil {
		return err
	}
	fmt.Printf("snapshot %s: %d CVEs, payload %d bytes, sha256 %s\nbundle: %s\n", m.SnapshotID, m.CVECount, m.PayloadSize, m.PayloadSHA256, c.out+".oculi-intel.zip")
	if len(b.warnings) > 0 {
		fmt.Fprintf(os.Stderr, "%d warnings (first 20):\n", len(b.warnings))
		for i, w := range b.warnings {
			if i == 20 {
				break
			}
			fmt.Fprintln(os.Stderr, "  ", w)
		}
	}
	return nil
}

type builder struct {
	c        cfg
	cat      *intel.Catalog
	http     *http.Client
	mu       sync.Mutex
	cves     map[string]*intel.CVE
	warnings []string
	lastNVD  time.Time
}

func (b *builder) warn(f string, a ...any) {
	b.mu.Lock()
	b.warnings = append(b.warnings, fmt.Sprintf(f, a...))
	b.mu.Unlock()
}

func (b *builder) parallel(ids []string, fn func(string)) {
	ch := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < max(1, b.c.workers); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range ch {
				fn(id)
			}
		}()
	}
	for _, id := range ids {
		ch <- id
	}
	close(ch)
	wg.Wait()
}

// get fetches a URL (or reads a local file) with size limit, retries on 403/429/5xx.
func (b *builder) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		f, err := os.Open(u)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return readMax(f, limit)
	}
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * 3 * time.Second)
		}
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if b.c.nvdKey != "" && strings.Contains(u, "services.nvd.nist.gov") {
			req.Header.Set("apiKey", b.c.nvdKey)
		}
		res, err := b.http.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := readMax(res.Body, limit)
		res.Body.Close()
		switch {
		case res.StatusCode == 404:
			return nil, fmt.Errorf("HTTP 404")
		case res.StatusCode == 403 || res.StatusCode == 429 || res.StatusCode >= 500:
			last = fmt.Errorf("HTTP %d", res.StatusCode)
			continue
		case res.StatusCode != 200:
			return nil, fmt.Errorf("HTTP %d", res.StatusCode)
		}
		if err != nil {
			return nil, err
		}
		return body, nil
	}
	return nil, last
}

func readMax(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("response exceeds size limit")
	}
	return body, nil
}

// addNVD accepts either a bare NVD cve object or an API envelope.
func (b *builder) addNVD(raw []byte, want string) {
	var env struct {
		Vulns []struct {
			CVE json.RawMessage `json:"cve"`
		} `json:"vulnerabilities"`
	}
	objs := []json.RawMessage{raw}
	if json.Unmarshal(raw, &env) == nil && env.Vulns != nil {
		objs = nil
		for _, v := range env.Vulns {
			objs = append(objs, v.CVE)
		}
	}
	for _, o := range objs {
		cv, warns, err := intel.FromNVD(o)
		if err != nil {
			b.warn("NVD record %s: %v", want, err)
			continue
		}
		for _, w := range warns {
			b.warn("%s", w)
		}
		b.mu.Lock()
		if old, ok := b.cves[cv.ID]; !ok || old.Modified < cv.Modified {
			b.cves[cv.ID] = &cv
		}
		b.mu.Unlock()
	}
}

// nvdByCPE pages through NVD results for every CVE whose configurations match the product.
func (b *builder) nvdByCPE(ctx context.Context, key string) (int, error) {
	parts := strings.SplitN(key, ":", 3)
	vm := "cpe:2.3:" + parts[0] + ":" + escapeCPE(parts[1]) + ":" + escapeCPE(parts[2])
	start, total, got := 0, -1, 0
	for total < 0 || start < total {
		// NVD rate limit: 5 requests / 30 s without key, 50 / 30 s with key.
		gap := 6500 * time.Millisecond
		if b.c.nvdKey != "" {
			gap = 700 * time.Millisecond
		}
		if b.c.nvdGap > 0 {
			gap = b.c.nvdGap
		}
		if wait := time.Until(b.lastNVD.Add(gap)); wait > 0 {
			time.Sleep(wait)
		}
		b.lastNVD = time.Now()
		q := url.Values{"virtualMatchString": {vm}, "resultsPerPage": {"2000"}, "startIndex": {strconv.Itoa(start)}, "noRejected": {""}}
		raw, err := b.get(ctx, b.c.nvdAPI+"?"+strings.Replace(q.Encode(), "noRejected=", "noRejected", 1), 256<<20)
		if err != nil {
			return got, err
		}
		var page struct {
			Total int `json:"totalResults"`
			Per   int `json:"resultsPerPage"`
			Vulns []struct {
				CVE json.RawMessage `json:"cve"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return got, fmt.Errorf("invalid NVD page: %w", err)
		}
		total = page.Total
		if total > b.c.maxPerCPE {
			return got, fmt.Errorf("%d results exceed -max-per-cpe", total)
		}
		for _, v := range page.Vulns {
			b.addNVD(v.CVE, key)
			got++
		}
		if len(page.Vulns) == 0 {
			break
		}
		start += len(page.Vulns)
	}
	return got, nil
}

func escapeCPE(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			sb.WriteRune('\\')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func (b *builder) loadKEV(ctx context.Context) (intel.KEVCatalog, intel.SourceInfo) {
	info := intel.SourceInfo{Name: "CISA Known Exploited Vulnerabilities", URL: b.c.kevSrc, Retrieved: time.Now().UTC().Format(time.RFC3339), Terms: "U.S. Government work (CISA); public domain in the United States"}
	raw, err := b.get(ctx, b.c.kevSrc, 16<<20)
	if err != nil {
		info.Note = "not retrieved: " + err.Error()
		return intel.KEVCatalog{}, info
	}
	k, err := intel.ParseKEV(raw)
	if err != nil {
		info.Note = "invalid: " + err.Error()
		return intel.KEVCatalog{}, info
	}
	info.Version, info.Records = k.Version, len(k.Items)
	return k, info
}

// kevVendorRelevant selects KEV rows whose vendor/product could map to a catalog identity.
var kevRelevant = regexp.MustCompile(`(?i)^(microsoft\|(windows|win32k|edge|.*windows.*)|google\|(chrom|chrome)|mozilla\||rarlab\||7-zip\||adobe\|(acrobat|reader)|videolan\||notepad|putty|winscp|teamviewer|anydesk|git\||python|node|oracle\|(java|virtualbox)|docker\|desktop|openvpn|libreoffice|wireshark|keepass|gimp|zoom\|)`)

func kevVendorRelevant(r intel.KEVRecord) bool {
	return kevRelevant.MatchString(strings.ToLower(r.Vendor) + "|" + strings.ToLower(r.Product))
}

func referencedKeys(cv *intel.CVE, cat *intel.Catalog) []string {
	all := map[string]bool{}
	for _, k := range cat.AllCPEKeys() {
		all[k] = true
	}
	found := map[string]bool{}
	for _, c := range cv.NVD {
		for _, n := range c.Nodes {
			for _, m := range n.Matches {
				if p, err := intel.ParseCPE(m.CPE); err == nil && m.Vulnerable && all[p.Key()] {
					found[p.Key()] = true
				}
			}
		}
	}
	for _, rs := range cv.ADP {
		for _, s := range rs.CPEs {
			if p, err := intel.ParseCPE(s); err == nil && all[p.Key()] {
				found[p.Key()] = true
			}
		}
	}
	cna := map[string]string{}
	for _, e := range cat.Entries {
		for _, a := range e.CNA {
			cna[a.Vendor+"|"+a.Product] = e.CPEs[0].Key()
		}
	}
	for _, rs := range cv.CNA {
		v, p := intel.NormalizeName(rs.Vendor), intel.NormalizeName(rs.Product)
		if k, ok := cna[v+"|"+p]; ok {
			found[k] = true
		}
		if v == "microsoft" && strings.HasPrefix(p, "windows ") {
			found["o:microsoft:windows-msrc"] = true
		}
	}
	var out []string
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (b *builder) referencesTrustedVendor(cv *intel.CVE) bool {
	for _, k := range referencedKeys(cv, b.cat) {
		if strings.HasPrefix(k, "o:microsoft:") || k == "a:microsoft:edge_chromium" || k == "a:microsoft:edge" ||
			strings.HasPrefix(k, "a:mozilla:") || strings.HasPrefix(k, "a:python:") {
			return true
		}
	}
	return false
}

func (b *builder) epss(ctx context.Context, cves []intel.CVE) (map[string]intel.EPSSInfo, error) {
	out := map[string]intel.EPSSInfo{}
	var firstErr error
	for i := 0; i < len(cves); i += 100 {
		j := min(i+100, len(cves))
		var ids []string
		for _, c := range cves[i:j] {
			ids = append(ids, c.ID)
		}
		raw, err := b.get(ctx, b.c.epssURL+"?cve="+strings.Join(ids, ","), 2<<20)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if i == 0 {
				return out, err // source unreachable: do not hammer it
			}
			continue
		}
		got, err := intel.ParseEPSS(raw)
		if err != nil {
			return out, err
		}
		for k, v := range got {
			out[k] = v
		}
	}
	return out, firstErr
}

func readIDs(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.ToUpper(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]))
		if line == "" {
			continue
		}
		if !intel.ValidCVEID(line) {
			return nil, fmt.Errorf("invalid CVE ID %q in %s", line, path)
		}
		out = append(out, line)
	}
	return out, nil
}

// expand fills URL templates: {id}, {year}, {nvdbucket} (CVE-2024-11477 → CVE-2024-114xx), {cve5bucket} (11xxx).
func expand(t, id string) string {
	p := strings.Split(id, "-")
	num := p[2]
	n, _ := strconv.Atoi(num)
	r := strings.NewReplacer("{id}", id, "{year}", p[1], "{nvdbucket}", "CVE-"+p[1]+"-"+num[:len(num)-2]+"xx", "{cve5bucket}", strconv.Itoa(n/1000)+"xxx")
	return r.Replace(t)
}

func dedupe(s []string) []string {
	sort.Strings(s)
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// nonWindowsTargets are CPE target_sw values for software that is never an
// installed Windows program (mobile/macOS/Linux builds, CMS plugins, language
// packages, browser extensions). Matches limited to these are dropped.
var nonWindowsTargets = map[string]bool{
	"android": true, "iphone_os": true, "ipados": true, "ios": true, "macos": true, "mac_os_x": true, "mac_os": true, "linux": true,
	"wordpress": true, "joomla\\!": true, "joomla!": true, "joomla": true, "drupal": true, "magento": true, "prestashop": true, "typo3": true, "moodle": true,
	"node.js": true, "python": true, "ruby": true, "rails": true, "rust": true, "go": true, "golang": true, "perl": true, "php": true, "pypi": true, "npm": true,
	"chrome": true, "firefox": true, "jenkins": true, "confluence": true, "jira": true, "kubernetes": true,
}

// relevantFull keeps a CVE when at least one vulnerable criterion names an
// application (part a) that could be installed on Windows, or a Windows OS release.
func relevantFull(cv *intel.CVE) bool {
	for _, c := range cv.NVD {
		for _, n := range c.Nodes {
			for _, m := range n.Matches {
				if !m.Vulnerable {
					continue
				}
				p, err := intel.ParseCPE(m.CPE)
				if err != nil {
					continue
				}
				if p.Part == "o" && p.Vendor == "microsoft" && strings.HasPrefix(p.Product, "windows") {
					return true
				}
				if p.Part == "a" && !nonWindowsTargets[strings.ToLower(p.TargetSW)] {
					return true
				}
			}
		}
	}
	return false
}

// slim trims fields the endpoint does not need in a full snapshot (keeps the
// most useful references: patch / vendor advisory / release notes first).
func slim(cv *intel.CVE) {
	const maxRefs = 8
	if len(cv.References) > maxRefs {
		rank := func(r intel.Reference) int {
			for _, t := range r.Tags {
				switch t {
				case "Patch", "Vendor Advisory":
					return 0
				case "Release Notes", "Mitigation":
					return 1
				}
			}
			return 2
		}
		sort.SliceStable(cv.References, func(i, j int) bool { return rank(cv.References[i]) < rank(cv.References[j]) })
		cv.References = cv.References[:maxRefs]
	}
}

// trustedCNAs are CNAs whose own affected data OCULI uses; their CVEs that NVD has
// not analysed yet are fetched from the CVE Program.
var trustedCNAs = map[string]bool{"secure@microsoft.com": true, "security@mozilla.org": true, "cna@python.org": true}

// loadFeed streams a complete NVD 2.0 feed ({"timestamp":..., "cve_items":[...]}
// or the API's {"vulnerabilities":[{"cve":...}]}) and keeps relevant records.
func (b *builder) loadFeed(path string) (n int, ts string, trustedNoCfg []string, err error) {
	if path == "" {
		return 0, "", nil, errors.New("-nvd-feed is required for -mode nvd-feed")
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, "", nil, err
	}
	defer f.Close()
	var r io.Reader = bufio.NewReaderSize(f, 4<<20)
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return 0, "", nil, err
		}
		r = zr
	}
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return 0, "", nil, errors.New("feed is not a JSON object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return n, ts, nil, err
		}
		switch t {
		case "timestamp":
			dec.Decode(&ts)
		case "cve_items", "vulnerabilities":
			wrapped := t == "vulnerabilities"
			if t, err := dec.Token(); err != nil || t != json.Delim('[') {
				return n, ts, nil, errors.New("feed item list is not an array")
			}
			for dec.More() {
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return n, ts, nil, fmt.Errorf("feed record %d: %w", n, err)
				}
				n++
				if n%50000 == 0 {
					fmt.Fprintf(os.Stderr, "feed: %d records read, %d kept\n", n, len(b.cves))
				}
				if wrapped {
					var w struct {
						CVE json.RawMessage `json:"cve"`
					}
					if json.Unmarshal(raw, &w) != nil {
						continue
					}
					raw = w.CVE
				}
				cv, _, err := intel.FromNVD(raw)
				if err != nil || cv.State == "REJECTED" {
					continue
				}
				if len(cv.NVD) == 0 {
					var hdr struct {
						Source string `json:"sourceIdentifier"`
					}
					if json.Unmarshal(raw, &hdr) == nil && trustedCNAs[hdr.Source] {
						trustedNoCfg = append(trustedNoCfg, cv.ID)
					}
					continue
				}
				if !relevantFull(&cv) {
					if k := referencedKeys(&cv, b.cat); len(k) == 0 {
						continue
					}
				}
				b.cves[cv.ID] = &cv
			}
			dec.Token()
		default:
			var skip json.RawMessage
			dec.Decode(&skip)
		}
	}
	fmt.Fprintf(os.Stderr, "feed %s: %d records read, %d kept, %d trusted-CNA records without NVD configuration\n", ts, n, len(b.cves), len(trustedNoCfg))
	return n, ts, trustedNoCfg, nil
}

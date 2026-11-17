package intel

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// Size limits applied before and during decoding (defence against corrupt or hostile files).
const (
	MaxManifestBytes  = 1 << 20
	MaxPayloadGzBytes = 96 << 20
	MaxPayloadBytes   = 768 << 20
	MaxCVEs           = 400000
	ManifestFile      = "manifest.json"
	PayloadFile       = "snapshot.json.gz"
)

var keyIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// TrustedKeys maps a key ID to an Ed25519 public key.
type TrustedKeys map[string]ed25519.PublicKey

// ParsePublicKey decodes "keyid:base64(pubkey)".
func ParsePublicKey(line string) (string, ed25519.PublicKey, error) {
	id, b64, ok := strings.Cut(strings.TrimSpace(line), ":")
	if !ok || !keyIDRe.MatchString(id) {
		return "", nil, fmt.Errorf("public key must be keyid:base64")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("invalid Ed25519 public key")
	}
	return id, ed25519.PublicKey(b), nil
}

func manifestSigningBytes(m Manifest) ([]byte, error) {
	m.Signature = ""
	return json.Marshal(m)
}

// SignManifest signs m in place.
func SignManifest(m *Manifest, keyID string, priv ed25519.PrivateKey) error {
	if !keyIDRe.MatchString(keyID) || len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid signing key")
	}
	m.KeyID = keyID
	b, err := manifestSigningBytes(*m)
	if err != nil {
		return err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
	return nil
}

// VerifyManifest checks schema, key and signature.
func VerifyManifest(m Manifest, keys TrustedKeys) error {
	if m.Schema != SchemaVersion {
		return fmt.Errorf("unsupported snapshot schema %d (this build understands %d)", m.Schema, SchemaVersion)
	}
	pub, ok := keys[m.KeyID]
	if !ok {
		return fmt.Errorf("snapshot signed with unknown key %q", m.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("snapshot signature malformed")
	}
	b, err := manifestSigningBytes(m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return fmt.Errorf("snapshot signature does not verify")
	}
	if m.PayloadFile != PayloadFile || m.PayloadSize <= 0 || m.PayloadSize > MaxPayloadGzBytes || len(m.PayloadSHA256) != 64 {
		return fmt.Errorf("snapshot manifest payload fields invalid")
	}
	return nil
}

// Snapshot is a verified, indexed intelligence snapshot.
//
// A complete snapshot holds ~250,000 CVEs (~460 MB of JSON). Keeping them as Go
// structs would cost well over 1 GB of RAM on the endpoint, so records are kept
// as compact JSON in flate-compressed chunks of ~256 KB and decoded on demand.
// The builder orders records by product, so one product's CVEs share chunks.
type Snapshot struct {
	Manifest Manifest
	count    int
	byID     map[string]int32
	byCPE    map[string][]int32
	byCNA    map[string][]int32
	loc      []recLoc
	chunks   [][]byte
	coverage map[string]Coverage

	mu    sync.Mutex
	cache map[int32][]byte // decompressed chunks (small, bounded)
	order []int32
}

type recLoc struct {
	chunk    int32
	off, len uint32
}

const (
	chunkTarget = 256 << 10
	cacheChunks = 24
)

// ReadManifestFS reads and verifies only the signed manifest (cheap): used to
// pick the newest snapshot before paying for a full load.
func ReadManifestFS(fsys fs.FS, keys TrustedKeys) (Manifest, error) {
	var m Manifest
	mb, err := readLimited(fsys, ManifestFile, MaxManifestBytes)
	if err != nil {
		return m, fmt.Errorf("manifest: %w", err)
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		return m, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	return m, VerifyManifest(m, keys)
}

// VerifyFilesFS checks the signed manifest and the payload size and SHA-256
// without decoding the payload (used to re-check files after they were copied).
func VerifyFilesFS(fsys fs.FS, keys TrustedKeys) (Manifest, error) {
	m, err := ReadManifestFS(fsys, keys)
	if err != nil {
		return m, err
	}
	pb, err := readLimited(fsys, PayloadFile, MaxPayloadGzBytes)
	if err != nil {
		return m, fmt.Errorf("payload: %w", err)
	}
	sum := sha256.Sum256(pb)
	if int64(len(pb)) != m.PayloadSize || hex.EncodeToString(sum[:]) != strings.ToLower(m.PayloadSHA256) {
		return m, fmt.Errorf("payload does not match the signed manifest")
	}
	return m, nil
}

// ReadSnapshotFS loads and fully verifies a snapshot from fsys (disk dir or embedded FS).
func ReadSnapshotFS(fsys fs.FS, keys TrustedKeys) (*Snapshot, error) {
	m, err := ReadManifestFS(fsys, keys)
	if err != nil {
		return nil, err
	}
	return readPayload(fsys, m)
}

func readPayload(fsys fs.FS, m Manifest) (*Snapshot, error) {
	pb, err := readLimited(fsys, PayloadFile, MaxPayloadGzBytes)
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	if int64(len(pb)) != m.PayloadSize {
		return nil, fmt.Errorf("payload size %d does not match manifest %d (truncated or interrupted download)", len(pb), m.PayloadSize)
	}
	sum := sha256.Sum256(pb)
	if hex.EncodeToString(sum[:]) != strings.ToLower(m.PayloadSHA256) {
		return nil, fmt.Errorf("payload SHA-256 mismatch (corrupted file)")
	}
	zr, err := gzip.NewReader(bytes.NewReader(pb))
	if err != nil {
		return nil, fmt.Errorf("payload is not gzip: %w", err)
	}
	lr := &io.LimitedReader{R: zr, N: MaxPayloadBytes + 1}
	pb = nil
	s := newSnapshot(m)
	if err := s.decodePayload(json.NewDecoder(bufio.NewReaderSize(lr, 1<<20))); err != nil {
		if lr.N <= 0 {
			return nil, fmt.Errorf("payload exceeds size limit")
		}
		return nil, err
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("payload exceeds size limit")
	}
	return s, s.finish()
}

func newSnapshot(m Manifest) *Snapshot {
	s := &Snapshot{Manifest: m, byID: map[string]int32{}, byCPE: map[string][]int32{}, byCNA: map[string][]int32{}, coverage: map[string]Coverage{}, cache: map[int32][]byte{}}
	for _, c := range m.Coverage {
		s.coverage[c.CPE] = c
	}
	return s
}

// decodePayload streams {"schema":N,"cves":[...]} without holding the whole
// document. Records are grouped into ~256 KB batches; each batch is parsed,
// validated and compressed by a worker pool, then merged in order, so ordinals
// (and therefore every index) are deterministic.
func (s *Snapshot) decodePayload(dec *json.Decoder) error {
	bad := func(what string) error { return fmt.Errorf("payload is not valid JSON: %s", what) }
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return bad("expected object")
	}
	schema := -1
	ld := newLoader(s)
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			ld.abort()
			return bad(err.Error())
		}
		key, _ := t.(string)
		switch key {
		case "schema":
			if err := dec.Decode(&schema); err != nil {
				ld.abort()
				return bad("schema")
			}
		case "cves":
			if t, err := dec.Token(); err != nil || t != json.Delim('[') {
				ld.abort()
				return bad("cves is not an array")
			}
			for dec.More() {
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					ld.abort()
					return bad(err.Error())
				}
				if err := ld.push(raw); err != nil {
					ld.abort()
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				ld.abort()
				return bad(err.Error())
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				ld.abort()
				return bad(err.Error())
			}
		}
	}
	if err := ld.close(); err != nil {
		return err
	}
	if schema != SchemaVersion {
		return fmt.Errorf("payload schema %d unsupported", schema)
	}
	return nil
}

// indexRec is the subset of a record needed for indexing (cheaper than a full CVE decode).
type indexRec struct {
	ID  string `json:"id"`
	NVD []struct {
		Nodes []struct {
			Matches []struct {
				Vulnerable bool   `json:"v"`
				CPE        string `json:"cpe"`
			} `json:"m"`
		} `json:"nodes"`
	} `json:"nvd"`
	ADP []struct {
		CPEs []string `json:"cpes"`
	} `json:"adp"`
	CNA []struct {
		Vendor  string `json:"vendor"`
		Product string `json:"product"`
	} `json:"cna"`
}

type batchIn struct {
	seq  int
	recs [][]byte
}

type batchOut struct {
	seq   int
	err   error
	ids   []string
	keys  [][]string
	cna   [][]string
	offs  []uint32
	lens  []uint32
	chunk []byte
}

type loader struct {
	s       *Snapshot
	in      chan batchIn
	out     chan batchOut
	cur     batchIn
	curSize int
	seq     int
	wg      sync.WaitGroup
	mergeWG sync.WaitGroup
	mergeEr error
}

func newLoader(s *Snapshot) *loader {
	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	l := &loader{s: s, in: make(chan batchIn, n*2), out: make(chan batchOut, n*2)}
	for i := 0; i < n; i++ {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			for b := range l.in {
				l.out <- processBatch(b)
			}
		}()
	}
	l.mergeWG.Add(1)
	go l.merge()
	return l
}

func (l *loader) push(raw []byte) error {
	l.cur.recs = append(l.cur.recs, raw)
	l.curSize += len(raw)
	if l.curSize >= chunkTarget {
		l.send()
	}
	return nil
}

func (l *loader) send() {
	if len(l.cur.recs) == 0 {
		return
	}
	l.cur.seq = l.seq
	l.seq++
	l.in <- l.cur
	l.cur, l.curSize = batchIn{}, 0
}

func (l *loader) close() error {
	l.send()
	close(l.in)
	l.wg.Wait()
	close(l.out)
	l.mergeWG.Wait()
	return l.mergeEr
}

func (l *loader) abort() { _ = l.close() }

// merge applies batch results strictly in sequence order.
func (l *loader) merge() {
	defer l.mergeWG.Done()
	pending := map[int]batchOut{}
	next := 0
	for b := range l.out {
		pending[b.seq] = b
		for {
			r, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			next++
			if l.mergeEr == nil {
				l.mergeEr = l.s.apply(r)
			}
		}
	}
}

func processBatch(b batchIn) batchOut {
	o := batchOut{seq: b.seq}
	var buf bytes.Buffer
	cpeKey := map[string]string{} // criteria are often repeated within a batch
	for i, raw := range b.recs {
		var r indexRec
		if err := json.Unmarshal(raw, &r); err != nil {
			o.err = fmt.Errorf("payload record is not valid: %v", err)
			return o
		}
		if !ValidCVEID(r.ID) {
			o.err = fmt.Errorf("payload record %d of batch %d has invalid ID", i, b.seq)
			return o
		}
		keys := map[string]bool{}
		for _, c := range r.NVD {
			for _, n := range c.Nodes {
				for _, m := range n.Matches {
					k, ok := cpeKey[m.CPE]
					if !ok {
						cp, err := ParseCPE(m.CPE)
						if err != nil {
							o.err = fmt.Errorf("%s has malformed CPE", r.ID)
							return o
						}
						k = cp.Key()
						cpeKey[m.CPE] = k
					}
					if m.Vulnerable {
						keys[k] = true
					}
				}
			}
		}
		for _, rs := range r.ADP {
			for _, x := range rs.CPEs {
				if cp, err := ParseCPE(x); err == nil {
					keys[cp.Key()] = true
				}
			}
		}
		kl := make([]string, 0, len(keys))
		for k := range keys {
			kl = append(kl, k)
		}
		var cl []string
		for _, rs := range r.CNA {
			cl = append(cl, NormalizeName(rs.Vendor)+"|"+NormalizeName(rs.Product))
		}
		compact := raw
		if bytes.ContainsAny(raw, "\n\t\r") {
			var c bytes.Buffer
			if json.Compact(&c, raw) == nil {
				compact = c.Bytes()
			}
		}
		o.ids = append(o.ids, r.ID)
		o.keys = append(o.keys, kl)
		o.cna = append(o.cna, cl)
		o.offs = append(o.offs, uint32(buf.Len()))
		o.lens = append(o.lens, uint32(len(compact)))
		buf.Write(compact)
	}
	var z bytes.Buffer
	fw, _ := flate.NewWriter(&z, flate.BestSpeed)
	fw.Write(buf.Bytes())
	fw.Close()
	o.chunk = bytes.Clone(z.Bytes())
	return o
}

func (s *Snapshot) apply(b batchOut) error {
	if b.err != nil {
		return b.err
	}
	ci := int32(len(s.chunks))
	s.chunks = append(s.chunks, b.chunk)
	for j, id := range b.ids {
		if s.count >= MaxCVEs {
			return fmt.Errorf("payload has more than %d CVEs", MaxCVEs)
		}
		if _, dup := s.byID[id]; dup {
			return fmt.Errorf("payload has duplicate %s", id)
		}
		i := int32(s.count)
		s.count++
		s.byID[id] = i
		for _, k := range b.keys[j] {
			s.byCPE[k] = append(s.byCPE[k], i)
		}
		for _, k := range b.cna[j] {
			s.byCNA[k] = append(s.byCNA[k], i)
		}
		s.loc = append(s.loc, recLoc{chunk: ci, off: b.offs[j], len: b.lens[j]})
	}
	return nil
}

func (s *Snapshot) finish() error {
	if s.count != s.Manifest.CVECount {
		return fmt.Errorf("payload CVE count %d does not match manifest %d", s.count, s.Manifest.CVECount)
	}
	return nil
}

// NewSnapshot validates an in-memory payload against its manifest and builds the indexes.
func NewSnapshot(m Manifest, p Payload) (*Snapshot, error) {
	if p.Schema != SchemaVersion {
		return nil, fmt.Errorf("payload schema %d unsupported", p.Schema)
	}
	if len(p.CVEs) > MaxCVEs || len(p.CVEs) != m.CVECount {
		return nil, fmt.Errorf("payload CVE count %d does not match manifest %d", len(p.CVEs), m.CVECount)
	}
	s := newSnapshot(m)
	ld := newLoader(s)
	for i := range p.CVEs {
		raw, err := json.Marshal(&p.CVEs[i])
		if err != nil {
			ld.abort()
			return nil, err
		}
		ld.push(raw)
	}
	if err := ld.close(); err != nil {
		return nil, err
	}
	return s, s.finish()
}

// Len is the number of CVE records.
func (s *Snapshot) Len() int { return s.count }

// chunk returns a decompressed chunk (bounded cache).
func (s *Snapshot) chunk(i int32) ([]byte, error) {
	s.mu.Lock()
	if b, ok := s.cache[i]; ok {
		s.mu.Unlock()
		return b, nil
	}
	s.mu.Unlock()
	b, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(s.chunks[i])), 64<<20))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if _, ok := s.cache[i]; !ok {
		s.cache[i] = b
		s.order = append(s.order, i)
		for len(s.order) > cacheChunks {
			delete(s.cache, s.order[0])
			s.order = s.order[1:]
		}
	}
	s.mu.Unlock()
	return b, nil
}

// record decodes one CVE. Each call returns a fresh value the caller may keep.
func (s *Snapshot) record(i int32) *CVE {
	l := s.loc[i]
	b, err := s.chunk(l.chunk)
	if err != nil || int(l.off+l.len) > len(b) {
		return nil
	}
	var c CVE
	if json.Unmarshal(b[l.off:l.off+l.len], &c) != nil {
		return nil
	}
	for ci := range c.NVD {
		for ni := range c.NVD[ci].Nodes {
			for mi := range c.NVD[ci].Nodes[ni].Matches {
				mt := &c.NVD[ci].Nodes[ni].Matches[mi]
				if cp, err := ParseCPE(mt.CPE); err == nil {
					mt.parsed = &cp
				}
			}
		}
	}
	return &c
}

// Candidates returns CVEs that name the identity in any source (deduplicated, ID order).
func (s *Snapshot) Candidates(id *Identity) []*CVE {
	seen := map[int32]bool{}
	for _, r := range id.CPEs {
		for _, i := range s.byCPE[r.Key()] {
			seen[i] = true
		}
	}
	for _, a := range id.CNA {
		for _, i := range s.byCNA[a.Vendor+"|"+a.Product] {
			seen[i] = true
		}
	}
	idx := make([]int32, 0, len(seen))
	for i := range seen {
		idx = append(idx, i)
	}
	// Decode chunk by chunk so each chunk is decompressed once.
	sort.Slice(idx, func(a, b int) bool { return idx[a] < idx[b] })
	out := make([]*CVE, 0, len(idx))
	for _, i := range idx {
		if c := s.record(i); c != nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

// HasCPE reports whether any record names vendor:product (part a/o/h key).
func (s *Snapshot) HasCPE(key string) bool { return len(s.byCPE[key]) > 0 }

// CPEKeys calls fn for every product key that has at least one CVE.
func (s *Snapshot) CPEKeys(fn func(key string, n int)) {
	for k, v := range s.byCPE {
		fn(k, len(v))
	}
}

// Lookup returns a CVE by ID.
func (s *Snapshot) Lookup(id string) *CVE {
	if i, ok := s.byID[id]; ok {
		return s.record(i)
	}
	return nil
}

// CoverageFor reports whether the snapshot claims coverage for the identity:
// covered = at least one of its CPEs was collected; complete = all were collected completely.
// A snapshot built from the complete NVD feed covers every CPE ("all-cpes").
func (s *Snapshot) CoverageFor(id *Identity) (covered, complete bool, method string) {
	if s.Manifest.FullFeed {
		return true, true, "nvd-full-feed"
	}
	complete = true
	for _, r := range id.CPEs {
		if c, ok := s.coverage[r.Key()]; ok {
			covered = true
			method = c.Method
			if !c.Complete {
				complete = false
			}
		} else {
			complete = false
		}
	}
	return covered, covered && complete, method
}

// WriteSnapshot gzips the payload, fills in the manifest hashes, signs it and
// writes manifest.json + snapshot.json.gz into dir (which must not exist yet).
func WriteSnapshot(dir string, m Manifest, p Payload, keyID string, priv ed25519.PrivateKey) (Manifest, error) {
	// Order by primary product, then ID: a product's CVEs end up in the same
	// endpoint chunks (see Snapshot). Deterministic for identical input.
	prim := make(map[string]string, len(p.CVEs))
	for i := range p.CVEs {
		prim[p.CVEs[i].ID] = primaryKey(&p.CVEs[i])
	}
	sort.Slice(p.CVEs, func(i, j int) bool {
		a, b := prim[p.CVEs[i].ID], prim[p.CVEs[j].ID]
		if a != b {
			return a < b
		}
		return p.CVEs[i].ID < p.CVEs[j].ID
	})
	p.Schema = SchemaVersion
	raw, err := json.Marshal(p)
	if err != nil {
		return m, err
	}
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if _, err := zw.Write(raw); err != nil {
		return m, err
	}
	if err := zw.Close(); err != nil {
		return m, err
	}
	sum := sha256.Sum256(gz.Bytes())
	m.Schema = SchemaVersion
	m.PayloadFile = PayloadFile
	m.PayloadSize = int64(gz.Len())
	m.PayloadSHA256 = hex.EncodeToString(sum[:])
	m.CVECount = len(p.CVEs)
	if err := SignManifest(&m, keyID, priv); err != nil {
		return m, err
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	if _, err := os.Stat(dir); err == nil {
		return m, fmt.Errorf("output directory %s already exists", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return m, err
	}
	if err := os.WriteFile(filepath.Join(dir, PayloadFile), gz.Bytes(), 0o600); err != nil {
		return m, err
	}
	return m, os.WriteFile(filepath.Join(dir, ManifestFile), mb, 0o600)
}

func readLimited(fsys fs.FS, name string, limit int64) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return b, nil
}

// primaryKey is the smallest vulnerable product key of a record ("~" when none).
func primaryKey(c *CVE) string {
	best := "~"
	for _, cfg := range c.NVD {
		for _, n := range cfg.Nodes {
			for _, m := range n.Matches {
				if !m.Vulnerable {
					continue
				}
				if cp, err := ParseCPE(m.CPE); err == nil && cp.Key() < best {
					best = cp.Key()
				}
			}
		}
	}
	return best
}

// ForEach decodes every record in storage order (tests, tools; not used on the hot path).
func (s *Snapshot) ForEach(fn func(*CVE)) {
	for i := 0; i < s.count; i++ {
		if c := s.record(int32(i)); c != nil {
			fn(c)
		}
	}
}

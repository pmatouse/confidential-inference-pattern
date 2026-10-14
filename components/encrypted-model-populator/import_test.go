// SPDX-License-Identifier: Apache-2.0
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	name string
	data []byte
	kind byte
}

func archive(t *testing.T, entries []entry) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tr := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.kind
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0600, Size: int64(len(e.data)), Typeflag: typ}
		if typ == tar.TypeSymlink {
			h.Linkname = "/etc/passwd"
			h.Size = 0
		}
		if err := tr.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tr.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func fixture(t *testing.T) (Source, []byte, []byte) {
	t.Helper()
	disk := bytes.Repeat([]byte("synthetic-ciphertext-only\n"), 4096)
	s := Source{Format: format, Repository: "test/models", DiskDigest: shaDigest(disk), DiskBytes: int64(len(disk))}
	release, _ := json.Marshal(Release{s.Format, s.DiskDigest, s.DiskBytes})
	layer := archive(t, []entry{{"release.json", release, 0}, {"volume.raw", disk, 0}})
	return s, disk, layer
}
func target(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "disk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
func desc(raw []byte) Descriptor { return Descriptor{layerType, shaDigest(raw), int64(len(raw))} }

func TestCiphertextImportAndReadback(t *testing.T) {
	s, disk, layer := fixture(t)
	f := target(t)
	if err := importLayer(bytes.NewReader(layer), desc(layer), s, f); err != nil {
		t.Fatal(err)
	}
	f.Seek(0, io.SeekStart)
	got, _ := io.ReadAll(f)
	if !bytes.Equal(got, disk) {
		t.Fatal("wrong disk bytes")
	}
}

func TestPythonPublisherArchiveInteroperability(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("python3", "-c", `
import json, pathlib, sys
import publish
p = pathlib.Path(sys.argv[1])
with (p / "disk").open("xb") as f:
    f.write(b"non-secret transport fixture")
    f.truncate(64 << 20)
print(json.dumps(publish.pack(p / "disk", p)))
`, dir)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var r Release
	if err = json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	layer, err := os.ReadFile(filepath.Join(dir, "layer.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	s := Source{Format: r.Format, DiskDigest: r.DiskDigest, DiskBytes: r.DiskBytes}
	if err = importLayer(bytes.NewReader(layer), desc(layer), s, target(t)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectMalformedOrSubstitutedArtifact(t *testing.T) {
	s, disk, good := fixture(t)
	release, _ := json.Marshal(Release{s.Format, s.DiskDigest, s.DiskBytes})
	cases := map[string][]byte{
		"truncated-gzip":      good[:len(good)-4],
		"missing-release":     archive(t, []entry{{"volume.raw", disk, 0}}),
		"duplicate-disk":      archive(t, []entry{{"volume.raw", disk, 0}, {"volume.raw", disk, 0}}),
		"symlink":             archive(t, []entry{{"volume.raw", nil, tar.TypeSymlink}}),
		"traversal":           archive(t, []entry{{"../volume.raw", disk, 0}}),
		"unexpected-key-file": archive(t, []entry{{"key.bin", []byte("forbidden"), 0}}),
		"wrong-disk-size":     archive(t, []entry{{"volume.raw", disk[:len(disk)-1], 0}}),
		"wrong-disk-digest":   archive(t, []entry{{"release.json", release, 0}, {"volume.raw", bytes.Repeat([]byte{1}, len(disk)), 0}}),
		"wrong-release":       archive(t, []entry{{"release.json", []byte(`{"format":"not-supported"}`), 0}, {"volume.raw", disk, 0}}),
		"duplicate-release":   archive(t, []entry{{"release.json", release, 0}, {"release.json", release, 0}, {"volume.raw", disk, 0}}),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := importLayer(bytes.NewReader(raw), desc(raw), s, target(t)); err == nil {
				t.Fatal("bad artifact accepted")
			}
		})
	}
	t.Run("compressed-digest", func(t *testing.T) {
		d := desc(good)
		d.Digest = "sha256:" + strings.Repeat("0", 64)
		if importLayer(bytes.NewReader(good), d, s, target(t)) == nil {
			t.Fatal("unverified layer accepted")
		}
	})
	t.Run("compressed-size", func(t *testing.T) {
		d := desc(good)
		d.Size++
		if importLayer(bytes.NewReader(good), d, s, target(t)) == nil {
			t.Fatal("wrong layer size accepted")
		}
	})
}

type faultyTarget struct {
	*os.File
	syncFail, readCorrupt bool
}

func (f faultyTarget) Sync() error {
	if f.syncFail {
		return fmt.Errorf("injected flush failure")
	}
	return f.File.Sync()
}
func (f faultyTarget) Read(b []byte) (int, error) {
	n, e := f.File.Read(b)
	if f.readCorrupt && n > 0 {
		b[0] ^= 1
	}
	return n, e
}
func TestFlushAndReadbackFailures(t *testing.T) {
	s, _, layer := fixture(t)
	for _, f := range []faultyTarget{{target(t), true, false}, {target(t), false, true}} {
		if importLayer(bytes.NewReader(layer), desc(layer), s, f) == nil {
			t.Fatal("durability/readback failure accepted")
		}
	}
}

func TestRegistryTLSAndPinnedManifest(t *testing.T) {
	s, _, layer := fixture(t)
	m := Manifest{2, manifestType, Descriptor{configType, "sha256:" + strings.Repeat("a", 64), 2}, []Descriptor{desc(layer)}}
	raw, _ := json.Marshal(m)
	s.ManifestDigest = shaDigest(raw)
	tamper, redirect := false, false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("credential missing")
			w.WriteHeader(401)
			return
		}
		if redirect {
			http.Redirect(w, r, "https://attacker.invalid/", 302)
			return
		}
		if strings.Contains(r.URL.Path, "/manifests/") {
			if tamper {
				w.Write([]byte("bad"))
			} else {
				w.Write(raw)
			}
		} else {
			w.Write(layer)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	token := filepath.Join(dir, "token")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	os.WriteFile(token, []byte("fixture-token"), 0600)
	registry, err := NewRegistry(server.URL, ca, token)
	if err != nil {
		t.Fatal(err)
	}
	if err = Import(context.Background(), registry, s, target(t), s.DiskBytes); err != nil {
		t.Fatal(err)
	}
	if Import(context.Background(), registry, s, target(t), s.DiskBytes+1) == nil {
		t.Fatal("wrong device size accepted")
	}
	tamper = true
	if _, err = registry.Manifest(context.Background(), s); err == nil {
		t.Fatal("manifest replacement accepted")
	}
	tamper = false
	redirect = true
	if _, err = registry.Manifest(context.Background(), s); err == nil {
		t.Fatal("registry redirect followed")
	}
	if _, err = NewRegistry("http://registry.invalid", ca, token); err == nil {
		t.Fatal("plaintext registry permitted")
	}
}

func TestSourceMustPinNamespaceAndDigests(t *testing.T) {
	s := Source{format, "test/models", "sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64), 64 << 20}
	if err := s.Validate("test"); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Source){func(s *Source) { s.Repository = "other/models" }, func(s *Source) { s.ManifestDigest = "latest" }, func(s *Source) { s.DiskBytes = 0 }, func(s *Source) { s.Repository = "test/../../etc" }, func(s *Source) { s.Format = "plain" }} {
		copy := s
		edit(&copy)
		if copy.Validate("test") == nil {
			t.Fatal("bad source accepted")
		}
	}
}

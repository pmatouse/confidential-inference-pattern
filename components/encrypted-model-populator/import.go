// SPDX-License-Identifier: Apache-2.0
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

type Target interface {
	io.ReadWriteSeeker
	Sync() error
}

type countedReader struct {
	source io.Reader
	n      int64
}

func (r *countedReader) Read(b []byte) (int, error) {
	n, err := r.source.Read(b)
	r.n += int64(n)
	return n, err
}

// Import writes ciphertext only. Any failure leaves the temporary claim
// unpopulated: the controller must not hand it to the workload PVC.
func Import(ctx context.Context, registry *Registry, source Source, target Target, capacity int64) error {
	if capacity != source.DiskBytes {
		return fmt.Errorf("target capacity differs from pinned disk image")
	}
	layer, err := registry.Manifest(ctx, source)
	if err != nil {
		return err
	}
	body, err := registry.Get(ctx, "/v2/"+source.Repository+"/blobs/"+layer.Digest)
	if err != nil {
		return err
	}
	defer body.Close()
	return importLayer(body, layer, source, target)
}

func importLayer(body io.Reader, layer Descriptor, source Source, target Target) error {
	compressedHash := sha256.New()
	counted := &countedReader{source: io.TeeReader(io.LimitReader(body, layer.Size+1), compressedHash)}
	gz, err := gzip.NewReader(counted)
	if err != nil {
		return fmt.Errorf("invalid layer compression")
	}
	defer gz.Close()
	// Bound decompression, including archive framing/padding. Never extract paths.
	expanded := &countedReader{source: io.LimitReader(gz, source.DiskBytes+(1<<20)+1)}
	tr := tar.NewReader(expanded)
	foundDisk, foundRelease := false, false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid artifact tar: %w", err)
		}
		if h.Typeflag != tar.TypeReg || h.Linkname != "" || len(h.PAXRecords) != 0 {
			return fmt.Errorf("artifact contains non-regular entry")
		}
		switch h.Name {
		case "volume.raw":
			if foundDisk || h.Size != source.DiskBytes {
				return fmt.Errorf("duplicate or incorrectly sized disk entry")
			}
			foundDisk = true
			if _, err = target.Seek(0, io.SeekStart); err != nil {
				return err
			}
			diskHash := sha256.New()
			n, err := io.Copy(io.MultiWriter(target, diskHash), tr)
			if err != nil {
				return err
			}
			if n != source.DiskBytes || "sha256:"+hex.EncodeToString(diskHash.Sum(nil)) != source.DiskDigest {
				return fmt.Errorf("ciphertext disk digest mismatch")
			}
		case "release.json":
			if foundRelease || h.Size < 1 || h.Size > 4096 {
				return fmt.Errorf("duplicate or oversized release descriptor")
			}
			foundRelease = true
			raw, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			var r Release
			if err = decodeStrict(raw, &r); err != nil {
				return err
			}
			if r.Format != source.Format || r.DiskBytes != source.DiskBytes || r.DiskDigest != source.DiskDigest {
				return fmt.Errorf("release descriptor differs from source")
			}
		default:
			return fmt.Errorf("unexpected archive entry")
		}
	}
	if !foundDisk || !foundRelease {
		return fmt.Errorf("incomplete model artifact")
	}
	// Tar EOF is not gzip EOF. Consume bounded padding to validate the gzip CRC
	// and the digest of all compressed bytes, including any concatenated members.
	tail, err := io.ReadAll(expanded)
	if err != nil {
		return fmt.Errorf("invalid compressed trailer: %w", err)
	}
	for _, b := range tail {
		if b != 0 {
			return fmt.Errorf("nonzero data after tar end")
		}
	}
	if expanded.n > source.DiskBytes+(1<<20) {
		return fmt.Errorf("oversized expanded artifact")
	}
	if _, err = io.Copy(io.Discard, counted); err != nil {
		return err
	}
	if counted.n != layer.Size || "sha256:"+hex.EncodeToString(compressedHash.Sum(nil)) != layer.Digest {
		return fmt.Errorf("compressed layer size or digest mismatch")
	}
	if err = target.Sync(); err != nil {
		return err
	}
	if _, err = target.Seek(0, io.SeekStart); err != nil {
		return err
	}
	diskHash := sha256.New()
	n, err := io.CopyN(diskHash, target, source.DiskBytes)
	if err != nil || n != source.DiskBytes || "sha256:"+hex.EncodeToString(diskHash.Sum(nil)) != source.DiskDigest {
		return fmt.Errorf("ciphertext readback verification failed")
	}
	return nil
}

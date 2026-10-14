// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	group                = "storage.confidentialcontainers.org"
	kind                 = "EncryptedModelSource"
	version              = "v1alpha1"
	sourceResource       = "encryptedmodelsources"
	devicePath           = "/dev/model-target"
	format               = "luks-verity-v1"
	manifestType         = "application/vnd.docker.distribution.manifest.v2+json"
	configType           = "application/vnd.docker.container.image.v1+json"
	layerType            = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	maxDiskBytes   int64 = 64 << 30
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var repositoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}/[a-z0-9][a-z0-9._-]{0,127}$`)

type Source struct {
	Format         string `json:"format"`
	Repository     string `json:"repository"`
	ManifestDigest string `json:"manifestDigest"`
	DiskDigest     string `json:"diskDigest"`
	DiskBytes      int64  `json:"diskBytes"`
}

func (s Source) Validate(namespace string) error {
	if s.Format != format || !repositoryPattern.MatchString(s.Repository) ||
		!strings.HasPrefix(s.Repository, namespace+"/") ||
		!digestPattern.MatchString(s.ManifestDigest) || !digestPattern.MatchString(s.DiskDigest) ||
		s.DiskBytes < 64<<20 || s.DiskBytes > maxDiskBytes || s.DiskBytes%4096 != 0 {
		return fmt.Errorf("invalid immutable model source")
	}
	return nil
}

func decodeStrict(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

type Release struct {
	Format     string `json:"format"`
	DiskDigest string `json:"diskDigest"`
	DiskBytes  int64  `json:"diskBytes"`
}

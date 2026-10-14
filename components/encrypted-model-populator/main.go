// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	mode := flag.String("mode", "", "controller or import")
	namespace := flag.String("namespace", "", "isolated namespace")
	registry := flag.String("registry", "", "fixed HTTPS registry origin")
	image := flag.String("image", "", "digest-pinned importer image")
	storageClass := flag.String("storage-class", "", "allowed CSI storage class")
	serviceAccount := flag.String("importer-service-account", "encrypted-model-importer", "importer identity")
	caMap := flag.String("registry-ca-configmap", "encrypted-model-registry-ca", "registry CA bundle")
	kubeconfig := flag.String("kubeconfig", "", "development-only out-of-cluster kubeconfig path")
	raw := flag.String("source", "", "immutable source JSON")
	flag.Parse()
	fail := func(err error) { fmt.Fprintln(os.Stderr, "model population failed:", err); os.Exit(1) }
	if *namespace == "" || *registry == "" {
		fail(fmt.Errorf("namespace and registry required"))
	}
	switch *mode {
	case "controller":
		pieces := strings.Split(*image, "@")
		if len(pieces) != 2 || !digestPattern.MatchString(pieces[1]) || *storageClass == "" {
			fail(fmt.Errorf("pinned image and storage class required"))
		}
		Controller{*namespace, *image, *registry, *storageClass, *serviceAccount, *caMap}.Run(*kubeconfig)
	case "import":
		var source Source
		if err := decodeStrict([]byte(*raw), &source); err != nil {
			fail(err)
		}
		if err := source.Validate(*namespace); err != nil {
			fail(err)
		}
		client, err := NewRegistry(*registry, "/registry-ca/service-ca.crt", "/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			fail(err)
		}
		target, capacity, err := openTarget()
		if err != nil {
			fail(err)
		}
		defer target.Close()
		if err = Import(context.Background(), client, source, target, capacity); err != nil {
			fail(err)
		}
		fmt.Printf("CIPHERTEXT_IMPORT_VERIFIED bytes=%d digest=%s\n", source.DiskBytes, source.DiskDigest)
	default:
		fail(fmt.Errorf("invalid mode"))
	}
}

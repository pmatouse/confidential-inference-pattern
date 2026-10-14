// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	machinery "github.com/kubernetes-csi/lib-volume-populator/v3/populator-machinery"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"
	"strings"
	"testing"
)

func setupController(t *testing.T) (Controller, machinery.PopulatorParams) {
	t.Helper()
	source := Source{format, "test/models", "sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64), 64 << 20}
	raw, _ := json.Marshal(source)
	var spec map[string]any
	json.Unmarshal(raw, &spec)
	// Kubernetes unstructured JSON integer representation is int64.
	spec["diskBytes"] = source.DiskBytes
	pvc := &core.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "model", Namespace: "test", UID: "claim-id"}, Spec: core.PersistentVolumeClaimSpec{StorageClassName: ptr("lvms-test"), VolumeMode: ptr(core.PersistentVolumeBlock), AccessModes: []core.PersistentVolumeAccessMode{core.ReadWriteOncePod}, Resources: core.VolumeResourceRequirements{Requests: core.ResourceList{core.ResourceStorage: resource.MustParse("64Mi")}}}}
	prime := pvc.DeepCopy()
	prime.Name = "prime-claim-id"
	prime.UID = "prime-id"
	prime.ResourceVersion = "1"
	data := &unstructured.Unstructured{Object: map[string]any{"apiVersion": group + "/" + version, "kind": kind, "metadata": map[string]any{"namespace": "test", "name": "release", "uid": "source-id"}, "spec": spec}}
	client := fake.NewClientset(pvc, prime)
	return Controller{"test", "registry.invalid/importer@sha256:" + strings.Repeat("c", 64), "https://registry.invalid", "lvms-test", "importer", "ca"}, machinery.PopulatorParams{Pvc: pvc, PvcPrime: prime, Unstructured: data, KubeClient: client}
}

func TestPopulationIsNotRepeatedAfterDurableCompletion(t *testing.T) {
	c, p := setupController(t)
	ctx := context.Background()
	if err := c.start(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := c.start(ctx, p); err != nil {
		t.Fatal(err)
	}
	pods, _ := p.KubeClient.CoreV1().Pods("test").List(ctx, metav1.ListOptions{})
	if len(pods.Items) != 1 {
		t.Fatal("duplicate importer")
	}
	done, err := c.complete(ctx, p)
	if err != nil || done {
		t.Fatal("unfinished pod admitted")
	}
	pod := pods.Items[0]
	pod.Status.Phase = core.PodSucceeded
	p.KubeClient.CoreV1().Pods("test").UpdateStatus(ctx, &pod, metav1.UpdateOptions{})
	done, err = c.complete(ctx, p)
	if err != nil || done {
		t.Fatal("handoff before importer deletion observed", err)
	}
	p.PvcPrime, _ = p.KubeClient.CoreV1().PersistentVolumeClaims("test").Get(ctx, p.PvcPrime.Name, metav1.GetOptions{})
	if p.PvcPrime.Annotations[completionAnnotation] == "" {
		t.Fatal("success not recorded")
	}
	if err = c.start(ctx, p); err != nil {
		t.Fatal(err)
	}
	done, err = c.complete(ctx, p)
	if err != nil || !done {
		t.Fatal("completed import not acknowledged", err)
	}
	pods, _ = p.KubeClient.CoreV1().Pods("test").List(ctx, metav1.ListOptions{})
	if len(pods.Items) != 0 {
		t.Fatal("importer recreated after success")
	}
	p.Unstructured.SetUID("replacement-source")
	if c.start(ctx, p) == nil {
		t.Fatal("source recreation overwrote completed image")
	}
}

func TestFailedAndForeignImportersCannotHandoff(t *testing.T) {
	c, p := setupController(t)
	ctx := context.Background()
	c.start(ctx, p)
	pod, _ := p.KubeClient.CoreV1().Pods("test").Get(ctx, podName(p), metav1.GetOptions{})
	pod.Status.Phase = core.PodFailed
	p.KubeClient.CoreV1().Pods("test").UpdateStatus(ctx, pod, metav1.UpdateOptions{})
	if done, err := c.complete(ctx, p); err == nil || done {
		t.Fatal("failed importer handed off")
	}
	pod.Annotations[bindingAnnotation] = "forged"
	p.KubeClient.CoreV1().Pods("test").Update(ctx, pod, metav1.UpdateOptions{})
	if c.start(ctx, p) == nil {
		t.Fatal("foreign pod reused")
	}
}

func TestImporterPrivilegesAndScope(t *testing.T) {
	c, p := setupController(t)
	s, binding, err := c.source(p)
	if err != nil {
		t.Fatal(err)
	}
	pod := c.pod(p, s, binding)
	container := pod.Spec.Containers[0]
	if *container.SecurityContext.Privileged || *container.SecurityContext.AllowPrivilegeEscalation || !*container.SecurityContext.ReadOnlyRootFilesystem || len(container.SecurityContext.Capabilities.Add) != 0 || container.SecurityContext.Capabilities.Drop[0] != "ALL" {
		t.Fatal("unnecessary importer privilege")
	}
	if len(container.VolumeDevices) != 1 || container.VolumeDevices[0].DevicePath != devicePath {
		t.Fatal("wrong block target")
	}
	p.Pvc.Namespace = "production"
	if _, _, err = c.source(p); err == nil {
		t.Fatal("cross-namespace PVC accepted")
	}
	p.Pvc.Namespace = "test"
	p.Pvc.Spec.VolumeMode = ptr(core.PersistentVolumeFilesystem)
	if _, _, err = c.source(p); err == nil {
		t.Fatal("filesystem PVC accepted")
	}
}

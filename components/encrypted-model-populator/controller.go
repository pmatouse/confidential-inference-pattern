// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	machinery "github.com/kubernetes-csi/lib-volume-populator/v3/populator-machinery"
	core "k8s.io/api/core/v1"
	errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	informers "k8s.io/client-go/informers"
)

const completionAnnotation = group + "/import-complete"
const bindingAnnotation = group + "/import-binding"

type Controller struct{ Namespace, Image, Registry, StorageClass, ServiceAccount, CAConfigMap string }

func (c Controller) source(p machinery.PopulatorParams) (Source, string, error) {
	var s Source
	if p.Pvc == nil || p.PvcPrime == nil || p.Unstructured == nil ||
		p.Pvc.Namespace != c.Namespace || p.PvcPrime.Namespace != c.Namespace || p.Unstructured.GetNamespace() != c.Namespace ||
		p.Pvc.Spec.VolumeMode == nil || *p.Pvc.Spec.VolumeMode != core.PersistentVolumeBlock ||
		p.Pvc.Spec.StorageClassName == nil || *p.Pvc.Spec.StorageClassName != c.StorageClass ||
		p.Unstructured.GetUID() == "" || p.PvcPrime.UID == "" {
		return s, "", fmt.Errorf("source/PVC outside configured block population scope")
	}
	spec, ok, err := unstructured.NestedMap(p.Unstructured.Object, "spec")
	if err != nil || !ok {
		return s, "", fmt.Errorf("source spec absent")
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return s, "", err
	}
	if err = decodeStrict(raw, &s); err != nil {
		return s, "", err
	}
	if err = s.Validate(c.Namespace); err != nil {
		return s, "", err
	}
	requested := p.Pvc.Spec.Resources.Requests[core.ResourceStorage]
	if requested.Value() != s.DiskBytes {
		return s, "", fmt.Errorf("PVC requested size differs from complete image size")
	}
	if len(p.Pvc.Spec.AccessModes) != 1 || (p.Pvc.Spec.AccessModes[0] != core.ReadWriteOnce && p.Pvc.Spec.AccessModes[0] != core.ReadWriteOncePod) {
		return s, "", fmt.Errorf("model import requires an exclusive writable attachment")
	}
	binding := shaDigest([]byte(string(p.Pvc.UID) + "\n" + string(p.PvcPrime.UID) + "\n" + string(p.Unstructured.GetUID()) + "\n" + string(raw)))
	return s, binding, nil
}

func podName(p machinery.PopulatorParams) string { return "model-import-" + string(p.Pvc.UID) }
func ptr[T any](v T) *T                          { return &v }

func (c Controller) pod(p machinery.PopulatorParams, s Source, binding string) *core.Pod {
	raw, _ := json.Marshal(s)
	return &core.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: podName(p), Namespace: c.Namespace,
		Labels:          map[string]string{"app": "encrypted-model-importer", "coco.io/skip-initdata": "true"},
		Annotations:     map[string]string{bindingAnnotation: binding},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "PersistentVolumeClaim", Name: p.PvcPrime.Name, UID: p.PvcPrime.UID}},
	}, Spec: core.PodSpec{
		ServiceAccountName: c.ServiceAccount, AutomountServiceAccountToken: ptr(true), RestartPolicy: core.RestartPolicyNever,
		ActiveDeadlineSeconds: ptr(int64(1800)),
		SecurityContext:       &core.PodSecurityContext{RunAsUser: ptr(int64(0)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		Containers: []core.Container{{Name: "importer", Image: c.Image,
			Args:            []string{"--mode=import", "--namespace=" + c.Namespace, "--registry=" + c.Registry, "--source=" + string(raw)},
			SecurityContext: &core.SecurityContext{Privileged: ptr(false), AllowPrivilegeEscalation: ptr(false), ReadOnlyRootFilesystem: ptr(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
			Resources:       core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("64Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("2"), core.ResourceMemory: resource.MustParse("256Mi")}},
			VolumeDevices:   []core.VolumeDevice{{Name: "target", DevicePath: devicePath}},
			VolumeMounts:    []core.VolumeMount{{Name: "registry-ca", MountPath: "/registry-ca", ReadOnly: true}},
		}},
		Volumes: []core.Volume{
			{Name: "target", VolumeSource: core.VolumeSource{PersistentVolumeClaim: &core.PersistentVolumeClaimVolumeSource{ClaimName: p.PvcPrime.Name}}},
			{Name: "registry-ca", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: c.CAConfigMap}}}},
		},
	}}
}

func (c Controller) checkedPod(ctx context.Context, p machinery.PopulatorParams, s Source, binding string) (*core.Pod, error) {
	pod, err := p.KubeClient.CoreV1().Pods(c.Namespace).Get(ctx, podName(p), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	want := c.pod(p, s, binding)
	if pod.Annotations[bindingAnnotation] != binding || len(pod.Spec.Containers) != 1 ||
		pod.Spec.Containers[0].Image != c.Image || !reflect.DeepEqual(pod.Spec.Containers[0].Args, want.Spec.Containers[0].Args) ||
		pod.Spec.ServiceAccountName != c.ServiceAccount || len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].UID != p.PvcPrime.UID {
		return nil, fmt.Errorf("import pod ownership or source conflict")
	}
	return pod, nil
}

func (c Controller) start(ctx context.Context, p machinery.PopulatorParams) error {
	s, binding, err := c.source(p)
	if err != nil {
		return err
	}
	if done := p.PvcPrime.Annotations[completionAnnotation]; done != "" {
		if done != binding {
			return fmt.Errorf("completed import binding changed")
		}
		return nil
	}
	_, err = c.checkedPod(ctx, p, s, binding)
	if !errors.IsNotFound(err) {
		return err
	}
	_, err = p.KubeClient.CoreV1().Pods(c.Namespace).Create(ctx, c.pod(p, s, binding), metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		return fmt.Errorf("import pod creation raced; recheck ownership")
	}
	return err
}

func (c Controller) complete(ctx context.Context, p machinery.PopulatorParams) (bool, error) {
	s, binding, err := c.source(p)
	if err != nil {
		return false, err
	}
	pod, err := c.checkedPod(ctx, p, s, binding)
	if p.PvcPrime.Annotations[completionAnnotation] == binding && errors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if pod.Status.Phase == core.PodFailed {
		return false, fmt.Errorf("ciphertext import failed; temporary PVC retained")
	}
	if pod.Status.Phase != core.PodSucceeded {
		return false, nil
	}
	if p.PvcPrime.Annotations[completionAnnotation] != binding {
		patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"resourceVersion": p.PvcPrime.ResourceVersion, "annotations": map[string]string{completionAnnotation: binding}}})
		_, err = p.KubeClient.CoreV1().PersistentVolumeClaims(c.Namespace).Patch(ctx, p.PvcPrime.Name, types.MergePatchType, patch, metav1.PatchOptions{})
		if err != nil {
			return false, err
		}
	}
	// Persist success before removing the importer. Handoff waits until its Pod is
	// gone, so retries cannot run a writer against a workload-owned PVC.
	err = p.KubeClient.CoreV1().Pods(c.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &pod.UID}})
	if errors.IsNotFound(err) {
		err = nil
	}
	return false, err
}

func (c Controller) cleanup(ctx context.Context, p machinery.PopulatorParams) error {
	if p.Pvc == nil || p.Pvc.Namespace != c.Namespace {
		return fmt.Errorf("cleanup outside configured namespace")
	}
	pod, err := p.KubeClient.CoreV1().Pods(c.Namespace).Get(ctx, podName(p), metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.PvcPrime == nil || len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].UID != p.PvcPrime.UID {
		return fmt.Errorf("cleanup owner mismatch")
	}
	return p.KubeClient.CoreV1().Pods(c.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &pod.UID}})
}

func (c Controller) Run(kubeconfig string) {
	machinery.RunControllerWithConfig(machinery.VolumePopulatorConfig{
		AllowSameNamespace: true,
		Kubeconfig:         kubeconfig, Namespace: c.Namespace, Prefix: group,
		Gk: schema.GroupKind{Group: group, Kind: kind}, Gvr: schema.GroupVersionResource{Group: group, Version: version, Resource: sourceResource},
		CrossNamespace: false, SharedInformerOptions: []informers.SharedInformerOption{informers.WithNamespace(c.Namespace)},
		ProviderFunctionConfig: &machinery.ProviderFunctionConfig{PopulateFn: c.start, PopulateCompleteFn: c.complete, PopulateCleanupFn: c.cleanup},
	})
}

// SPDX-License-Identifier: Apache-2.0
// Local extension to the pinned Kubernetes CSI library; see ../LOCAL-CHANGES.md.
package populator_machinery

import (
	"context"
	"testing"

	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestOptInSameNamespaceCreatesPrimeButDoesNotRecurse(t *testing.T) {
	c, claims, sources, _, _, _ := initTest(testCase{populateFn: PopulateOperationStartSuccess})
	c.allowSameNamespace = true
	ns := testVpWorkingNamespace
	target := pvc(testPvcName, ns, "", testStorageClassName, "", testPvcUid, []string{pvFinalizer},
		dsf(testApiGroup, testDatasourceKind, testDataSourceName, ns), "", core.ReadWriteOnce)
	target.Spec.StorageClassName = nil
	c.handlePVC(target)
	if c.workqueue.Len() != 1 {
		t.Fatal("same-namespace informer event was not enqueued")
	}
	if _, err := c.kubeClient.CoreV1().PersistentVolumeClaims(ns).Create(context.Background(), target, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := claims.Informer().GetStore().Add(target); err != nil {
		t.Fatal(err)
	}
	source := ust()
	source.SetNamespace(ns)
	if err := sources.GetStore().Add(source); err != nil {
		t.Fatal(err)
	}
	// No storage class is needed to exercise namespace handling and prime creation.
	if err := c.syncPvc(context.Background(), "pvc/"+ns+"/"+target.Name, ns, target.Name); err != nil {
		t.Fatal(err)
	}
	prime, err := c.kubeClient.CoreV1().PersistentVolumeClaims(ns).Get(context.Background(), testPvcPrimeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal("same-namespace target ignored:", err)
	}
	if prime.Spec.DataSourceRef != nil {
		t.Fatal("prime inherited source and could recurse")
	}
	if err := claims.Informer().GetStore().Add(prime); err != nil {
		t.Fatal(err)
	}
	if err := c.syncPvc(context.Background(), "pvc/"+ns+"/"+prime.Name, ns, prime.Name); err != nil {
		t.Fatal(err)
	}
	list, err := c.kubeClient.CoreV1().PersistentVolumeClaims(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil || len(list.Items) != 2 {
		t.Fatal("recursive prime creation", err)
	}
}

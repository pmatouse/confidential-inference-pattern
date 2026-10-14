# Local same-namespace extension

This is the Apache-2.0 `populator-machinery` package, tests, module files and
license from Kubernetes CSI `lib-volume-populator` **v3.2.0**, commit
`6b100436f4ab9659f1b992c6e6410c760667aa94`. Original file digests are recorded in
`upstream-source-lock.json`. Examples and release tooling are omitted.

The only production change adds an opt-in `AllowSameNamespace` configuration
field. The default retains upstream behavior. When enabled, workload PVCs may
live in the controller's working namespace. Prime PVCs have no `dataSourceRef`,
so the existing source filter ignores them and prevents recursive population.

The caller scopes Kubernetes informers and mutation RBAC to one namespace. This
avoids introducing a second namespace and cluster-wide PVC/pod list privileges
just to satisfy the upstream working-namespace exclusion. The normal CR source
informer still uses upstream's cluster-wide read watch.

`same_namespace_test.go` covers target processing and non-recursion; all unchanged
upstream tests must also pass. This is a local development patch, not an upstream
release or a claim of OpenShift support. Re-evaluate it on dependency upgrades.

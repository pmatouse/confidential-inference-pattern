# Retained storage authority

Deploy in the trusted administration domain. A same-cluster installation is a
colocated trust topology; it does not protect authority history against that cluster's
administrator. This chart does not install a second Trustee or hold model keys.

1. Pin a freshly built authority image. Select a stable `installation`, a
   filesystem storage class and a separate release name. Install `mode: bootstrap`.
   The one-shot Job creates `/state/retained` exclusively, initializes its SQLite
   history and persists a bootstrap identity. A repeat validates the same history;
   partial state or a missing database fails closed. Do not delete it to retry.
2. Enroll reviewed model manifests and new volume initialization plans through the
   trusted release process. Create an existing Secret (or ExternalSecret output)
   with `tls.key` and `receipt.key`. Keep private material out of Helm values/Git.
3. Prepare a public ConfigMap with `server.json`, TLS certificate, AS signer, KBS
   CA and InitData. Use `/state/retained/authority.db` as the database, `/private`
   for private keys and `/config` for public files. Pin the public authority URL
   and its trust material in the guest release. Server configuration must require
   the qualified CPU/GPU appraisal and exact policy/InitData identities.
4. Upgrade the same release with `mode: serve`, `publicConfigMap` and
   `credentialsSecret`. A single replica uses Recreate. Normal startup verifies
   retained history and database identity before opening the server. It never
   calls fresh bootstrap. Credentials are copied by an unprivileged init container
   into memory-backed files with mode 0600, and mounted read-only in the server.

Neither mode has a service-account token or Kubernetes API permissions. The chart
uses restricted container settings, relies on OpenShift's assigned non-root UID
and group, and does not create a privileged SCC. Keep the same namespace/UID
allocation with the retained claim. A move to another ownership range requires an
explicit migration. PVC deletion is protected against Helm uninstall/Argo prune;
that does not change the underlying PV's reclaim policy or prevent administrator
removal. Back up history, enrollment records and receipt identity together.

The TCP readiness probe indicates listener availability only. Fresh attestation,
key release, initialization and inference are separate acceptance gates. No TLS
termination happens outside the authority. The optional workload/chat front end
has separate network and TLS configuration.

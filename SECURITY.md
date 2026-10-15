# Security and experimental status

The [security model](docs/security-model.md) documents InitData, attestation
coverage, key release, trusted components and residual threats.

Do not use this unqualified add-on as a production security boundary.
Report security concerns privately to the repository owner through the available
GitHub private reporting channel; if unavailable, request a private contact
without putting sensitive details in a public issue.

The privileged guest helper, release signer, storage authority and trusted
producer are part of the trusted computing base. The workload operator must not
receive a signer or decryption credential. A colocated authority is not
independent rollback protection against its own host administrator.

The installer never relaxes attestation policies, formats devices or enrolls
secrets. Its namespace-scoped controllers do not replace deployment approval.
Treat changes to runtime compatibility profiles and policy generation as security
changes requiring real-hardware qualification.

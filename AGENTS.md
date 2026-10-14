# Confidential inference add-on
Keep Kata, vLLM, OSC and shared CoCo services unchanged. New features belong in
this repository. Never import lab state, credentials, signed approvals or keys.
Use Helm 3 and explicit version pins. Do not install duplicate shared operators.
Run `make test` and `make lint` before committing. Hardware tests need an isolated
namespace and available GPU capacity; never stop existing inference automatically.
Do not label a deployment E2E-qualified without a fresh blank-volume test,
attestation, real inference and fresh-VM persistence evidence.

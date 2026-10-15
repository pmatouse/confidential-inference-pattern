# Stock runtime compatibility profiles

`osc-snp-nvidia-x86_64-v1.json` contains the tested OCI environment, mount and
privilege shapes for OSC 1.13's stock SNP/NVIDIA guest and the pinned NVIDIA
vLLM image. It contains no approvals, storage identities, hostnames, keys or
InitData. The helper image and Kubernetes service IP are deliberately blank.

Instantiate it with the new publisher's descriptor and explicit public site inputs:

```sh
python3 components/inference-release/profile.py \
  --template profiles/osc-snp-nvidia-x86_64-v1.json \
  --helper-image "$HELPER_IMAGE_DIGEST" \
  --service-host "$(oc get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}')" \
  --helper-build-name "$REVIEWED_HELPER_BUILD_NAME" \
  --helper-build-namespace "$REVIEWED_HELPER_BUILD_NAMESPACE" \
  --descriptor publisher-descriptor.json --identity "$DEMO_NAME" \
  --model-mount /model --data-mount /data --output qualified-profile.json
```

Review image metadata and the generated policy before signing. The explicit build
environment is bound into the policy and supplied to the helper; it is not a
wildcard. A different image/runtime version or a different TEE needs compatibility
and hardware qualification. Do not broaden policy rules merely to pass startup.
The template reproduces the demonstrated policy with its original public inputs.

This is the first supported profile, not a claim that arbitrary CoCo hardware is
already supported. Generic CRDs, ciphertext population and authority contracts are
separate from this platform-specific policy/attestation layer.

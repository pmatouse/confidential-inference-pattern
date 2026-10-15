# Add-on rule: all model-key tags are denied until explicitly bound. Existing
# stock rules apply only to other resource classes. KBS supplies data, not callers.
model_key_bindings := {{ toJson (.Values.kbs.resourcePolicy.modelKeyBindings | default dict) }}

model_submod_affirming(submod) if {
    submod["ear.status"] == "affirming"
    vector := submod["ear.trustworthiness-vector"]
    in_affirming_range(vector.hardware)
    in_affirming_range(vector.executables)
    in_affirming_range(vector.configuration)
}

allow if {
    data.plugin == "resource"
    count(data["resource-path"]) == 3
    data["resource-path"][0] == "default"
    data["resource-path"][1] == "model-keys"
    expected := model_key_bindings[data["resource-path"][2]]
    every _, submod in input.submods { model_submod_affirming(submod) }
    evidence := input.submods.cpu0["ear.veraison.annotated-evidence"]
    evidence.snp.measurement == expected.launchMeasurement
    evidence.init_data == expected.initData
    evidence.snp.policy_debug_allowed == false
    evidence.snp.policy_migrate_ma == false
    gpu := input.submods.gpu0["ear.veraison.annotated-evidence"].nvidia
    gpu["x-nvidia-overall-att-result"] == true
    gpu.secboot == true
    gpu.dbgstat == "disabled"
    gpu.measres == "success"
}

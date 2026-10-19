package policy
import rego.v1

fixture_vector := {"hardware":2,"executables":2,"configuration":2}
fixture_cpu := {"ear.status":"affirming","ear.trustworthiness-vector":fixture_vector,"ear.veraison.annotated-evidence":{"init_data":"approved-init","snp":{"measurement":"approved-launch","policy_debug_allowed":false,"policy_migrate_ma":false}}}
fixture_gpu := {"ear.status":"affirming","ear.trustworthiness-vector":fixture_vector,"ear.veraison.annotated-evidence":{"nvidia":{"x-nvidia-overall-att-result":true,"secboot":true,"dbgstat":"disabled","measres":"success"}}}
fixture_ear := {"submods":{"cpu0":fixture_cpu,"gpu0":fixture_gpu}}
fixture_bindings := {"rhoai-qwen-secrets":{"initData":"approved-init","launchMeasurement":"approved-launch"}}

test_reserved_class_denied_before_enrollment if {
    not allow with input as fixture_ear with data.plugin as "resource" with data["resource-path"] as ["default","rhoai-qwen-secrets","model-key"]
}
test_exact_guest_gets_each_demo_resource if {
    every resource in ["model-key","luks-passphrase","registry","tls-cert","tls-key"] {
        allow with input as fixture_ear with data.plugin as "resource" with data["resource-path"] as ["default","rhoai-qwen-secrets",resource] with data.policy.confidential_guest_bindings as fixture_bindings
    }
}
test_modified_guest_denied if {
    bad := json.patch(fixture_ear,[{"op":"replace","path":"/submods/cpu0/ear.veraison.annotated-evidence/init_data","value":"changed"}])
    not allow with input as bad with data.plugin as "resource" with data["resource-path"] as ["default","rhoai-qwen-secrets","model-key"] with data.policy.confidential_guest_bindings as fixture_bindings
}
test_cpu_only_denied_demo_but_keeps_existing_demo if {
    cpu_only := {"submods":{"cpu0":fixture_cpu}}
    not allow with input as cpu_only with data.plugin as "resource" with data["resource-path"] as ["default","rhoai-qwen-secrets","model-key"] with data.policy.confidential_guest_bindings as fixture_bindings
    allow with input as cpu_only with data.plugin as "resource" with data["resource-path"] as ["default","kbsres1","key3"]
}

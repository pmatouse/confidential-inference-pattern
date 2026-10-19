package agent_policy
import rego.v1

fixture_profile := {
    "namespace": "demo",
    "containers": {"POD": {
        "image": "pause", "args": ["/usr/bin/pod"],
        "environment": ["TERM=xterm"], "requiredEnvironment": [],
        "bindDestinations": ["/dev/shm"],
    }},
}

fixture_request := {
    "container_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "string_user": null, "shared_mounts": [], "devices": [],
    "OCI": {
        "Root": {"Path": "/run/kata-containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/rootfs"},
        "Hooks": null,
        "Process": {"Terminal": false, "Cwd": "/", "User": {"UID": 0, "GID": 0}, "Args": ["/usr/bin/pod"], "Env": ["TERM=xterm"]},
        "Annotations": {"io.kubernetes.pod.namespace": "demo", "io.kubernetes.container.name": "POD", "io.katacontainers.pkg.oci.container_type": "pod_sandbox"},
        "Linux": {"Namespaces": [{"Type": "mount", "Path": ""}], "UIDMappings": [], "GIDMappings": [], "Sysctl": {}, "RootfsPropagation": "", "Devices": []},
        "Mounts": [{"type_": "bind", "source": "/run/kata-containers/sandbox/shm", "destination": "/dev/shm", "options": ["rbind"]}],
    },
    "storages": [{"driver": "image_guest_pull", "source": "pause", "fstype": "overlay", "shared": false,
        "mount_point": "/run/kata-containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/rootfs",
        "driver_options": ["image_guest_pull={\"metadata\":{\"io.katacontainers.pkg.oci.container_type\":\"pod_sandbox\"}}"]}],
}

test_stock_sandbox_allowed if {
    CreateContainerRequest with input as fixture_request with data.agent_policy.profile as fixture_profile
}

test_arbitrary_command_denied if {
    changed := json.patch(fixture_request, [{"op": "replace", "path": "/OCI/Process/Args", "value": ["/bin/bash"]}])
    not CreateContainerRequest with input as changed with data.agent_policy.profile as fixture_profile
}

test_arbitrary_image_denied if {
    changed := json.patch(fixture_request, [{"op": "replace", "path": "/storages/0/source", "value": "attacker/image:latest"}])
    not CreateContainerRequest with input as changed with data.agent_policy.profile as fixture_profile
}

test_shell_environment_injection_denied if {
    changed := json.patch(fixture_request, [{"op": "add", "path": "/OCI/Process/Env/-", "value": "BASH_ENV=/host/attack.sh"}])
    not CreateContainerRequest with input as changed with data.agent_policy.profile as fixture_profile
}

test_host_backed_plaintext_memory_denied if {
    changed := json.patch(fixture_request, [{"op": "replace", "path": "/OCI/Mounts/0/source", "value": "/run/kata-containers/shared/containers/host-shm"}])
    not CreateContainerRequest with input as changed with data.agent_policy.profile as fixture_profile
}

test_executable_mount_override_denied if {
    changed := json.patch(fixture_request, [{"op": "replace", "path": "/OCI/Mounts/0/destination", "value": "/usr/bin"}])
    not CreateContainerRequest with input as changed with data.agent_policy.profile as fixture_profile
}

test_exec_and_policy_replacement_denied if {
    not ExecProcessRequest with input as {"process": {"Args": ["cat", "/mnt/storage/model/config.json"]}}
    not SetPolicyRequest with input as {"policy": "allow all"}
    not WriteStreamRequest with input as {}
}

test_private_guest_file_write_denied if {
    not CopyFileRequest with input as {"path": "/dev/shm/verified-chat/server.py", "file_type": "Regular", "file_size": 16}
}

test_staging_path_traversal_denied if {
    not CopyFileRequest with input as {"path": "/run/kata-containers/shared/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-scripts/../../attack", "file_type": "Regular", "file_size": 16}
}

test_guest_memory_storage_allowed if {
    storage_allowed({"driver": "ephemeral", "fstype": "tmpfs", "mount_point": "/run/kata-containers/sandbox/ephemeral/storage-ipc"})
    not storage_allowed({"driver": "virtio-fs", "fstype": "virtiofs", "mount_point": "/run/kata-containers/sandbox/ephemeral/storage-ipc"})
}

fixture_gpu := {"devices": [], "OCI": {"Linux": {"Devices": []}, "Annotations": {"cdi.k8s.io/vfio1": "nvidia.com/gpu=0"}}}
test_already_attached_gpu_allowed if {
    devices_allowed("main") with input as fixture_gpu
}
test_gpu_attachment_and_cdi_restricted if {
    changed := object.union(fixture_gpu, {"devices": [{"type_": "vfio-pci-gk"}]})
    devices_allowed("main") with input as changed
    bad := object.union(fixture_gpu, {"devices": [{"type_": "scsi"}]})
    not devices_allowed("main") with input as bad
    no_cdi := json.patch(fixture_gpu, [{"op":"replace","path":"/OCI/Annotations","value":{}}])
    not devices_allowed("main") with input as no_cdi
    host_node := json.patch(fixture_gpu, [{"op":"replace","path":"/OCI/Linux/Devices","value":[{"Path":"/dev/mem","Type":"c"}]}])
    not devices_allowed("main") with input as host_node
}

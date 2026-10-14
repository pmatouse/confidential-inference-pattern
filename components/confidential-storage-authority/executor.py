"""Trusted in-process initialization coordinator; NOT an attested RPC service.

The backend owns a resolved device and all storage effects. Its binding must come
from trusted provisioning/device resolution, never host annotations. The only
concrete backend currently provided is the disposable non-TEE kernel lab.
"""

from copy import deepcopy
from dataclasses import dataclass
import hashlib
from threading import Lock

from authority import Denied
from initialization import STEPS, canonical, validate_result


class RecoveryRequired(Denied):
    """Uncertain work must be reconciled separately; never rerun destructive I/O."""


@dataclass(frozen=True)
class DeviceBinding:
    volume_id: str
    provisioning_id: str
    device_bytes: int
    profile_sha256: str
    credential_uri: str


@dataclass(frozen=True)
class Completion:
    result: dict
    evidence: dict


class Executor:
    """Serialize one backend's initialization and retain failed-attempt tombstones.

    Authority/peer/backend are trusted dependencies, not user-deserialized inputs.
    A synchronous worker owns execution to completion; an API adapter must not
    cancel this worker merely because the requesting client disconnects. After a
    process death, the durable authority journal blocks replay. No auto recovery,
    cleanup, key delivery or authority ownership release is implemented here.
    """

    def __init__(self, authority, peer, backend):
        peer.validate()
        self.authority = authority
        self.peer = peer
        self.backend = backend
        self.lock = Lock()
        self.attempted = False
        self.finished = None

    def initialize(self, operation_id, generation):
        with self.lock:
            if self.attempted:
                raise RecoveryRequired("executor already consumed; inspect authority")
            # Consume locally before any call that can have an uncertain outcome.
            self.attempted = True
            binding = self.backend.binding
            record = self.authority.inspect(binding.volume_id)
            approval = record.get("initialization_approval")
            if (
                not approval
                or record["revoked"]
                or record["state"] != "Uninitialized"
                or record["owner"] is not None
                or record.get("initialization_steps")
                or record["policy_sha256"] != self.peer.policy_sha256
                or record["generation"] != generation
                or binding.provisioning_id != approval["plan"]["provisioning_id"]
                or binding.device_bytes != approval["plan"]["device_bytes"]
                or binding.profile_sha256 != record["profile_sha256"]
                or binding.credential_uri != record["credential_uri"]
            ):
                raise RecoveryRequired("fresh approved device binding required")
            # Read-only preflight must retain the descriptor/device identity used
            # by execute, verify geometry/profile and reject existing signatures.
            # Absence of signatures alone NEVER authorizes formatting.
            self.backend.preflight(deepcopy(record))
            context = self.authority.begin(
                binding.volume_id, self.peer, operation_id, "initialize", generation
            )
            if context["action"] != "plan-initialization":
                raise RecoveryRequired("initialization already has an owner")
            activation = context["owner"]["activation_id"]
            header = None
            final = None
            for step in STEPS:
                decision = self.authority.begin_initialization_step(
                    binding.volume_id, self.peer, activation, step
                )
                if (
                    decision["decision"] != "execute"
                    or decision["plan_sha256"] != approval["plan_sha256"]
                    or decision["owner"] != context["owner"]
                    or decision["generation"] != generation
                ):
                    raise RecoveryRequired("step is not a fresh bound decision")
                # Never retry execute, including on BaseException/cancellation.
                completion = self.backend.execute(step, deepcopy(context))
                final = validate_result(step, completion.result, header)
                header = final["header_sha256"]
                # Hash identifies backend-observed evidence, NOT attestation.
                evidence = {
                    "volume_id": binding.volume_id,
                    "activation_id": activation,
                    "session_sha256": self.peer.session_sha256,
                    "plan_sha256": approval["plan_sha256"],
                    "step_id": decision["step_id"],
                    "step": step,
                    "result": final,
                    "observed": completion.evidence,
                }
                evidence_sha256 = hashlib.sha256(
                    canonical(evidence).encode()
                ).hexdigest()
                self.authority.complete_initialization_step(
                    binding.volume_id,
                    self.peer,
                    activation,
                    decision["step_id"],
                    final,
                    evidence_sha256,
                )
            self.finished = self.authority.commit_ready(
                binding.volume_id,
                self.peer,
                activation,
                header,
                manifest_sha256=final["manifest_sha256"],
            )
            return deepcopy(self.finished)

-- Merge under resource.customizations.health.inference.confidentialcontainers.org_InferenceRelease
hs = {status = "Progressing", message = "Waiting for verified release"}
if obj.status == nil then return hs end
if obj.status.observedGeneration ~= obj.metadata.generation then return hs end
if obj.status.phase == "Blocked" then
  hs.status = "Degraded"
  hs.message = obj.status.reason or "Release blocked"
elseif obj.status.phase == "Ready" then
  for _, condition in ipairs(obj.status.conditions or {}) do
    if condition.type == "Ready" and condition.status == "True" and condition.reason == "E2EPassed" then
      hs.status = "Healthy"
      hs.message = "First boot and fresh-VM inference/persistence verified"
    end
  end
else
  hs.message = (obj.status.currentStage or "Validating") .. ": " .. (obj.status.reason or "")
end
return hs

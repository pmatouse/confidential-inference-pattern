#!/bin/bash
set -euo pipefail
. "${DEMO_CONFIG:-/opt/demo}/link.sh"
cd /mnt/storage/model
sha256sum -c "${DEMO_CONFIG:-/opt/demo}/model.sha256"
export TMPDIR=/mnt/storage/tmp HOME=/mnt/storage/cache HF_HOME=/mnt/storage/cache
export VLLM_CACHE_ROOT=/mnt/storage/cache/vllm TRITON_CACHE_DIR=/mnt/storage/cache/triton
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 VLLM_NO_USAGE_STATS=1
exec python3 -m vllm.entrypoints.openai.api_server \
  --model /mnt/storage/model --served-model-name qwen3-0.6b \
  --host 127.0.0.1 --port 8000 --dtype bfloat16 --max-model-len 2048 \
  --max-num-seqs 4 --gpu-memory-utilization 0.25 --enforce-eager \
  --attention-config '{"backend":"TRITON_ATTN"}' \
  --no-enable-flashinfer-autotune --no-enable-log-requests --generation-config vllm

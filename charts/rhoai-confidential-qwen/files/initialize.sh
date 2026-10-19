#!/bin/bash
set -euo pipefail
. "${DEMO_CONFIG:-/opt/demo}/link.sh"
mkdir -p /mnt/storage/model /mnt/storage/cache /mnt/storage/tmp
export TMPDIR=/mnt/storage/tmp HOME=/mnt/storage/cache HF_HOME=/mnt/storage/cache HF_HUB_CACHE=/mnt/storage/cache
cd /mnt/storage/model
if [ -f .complete ] && sha256sum -c "${DEMO_CONFIG:-/opt/demo}/model.sha256"; then
  echo 'MODEL_PERSISTENCE_HASHES_PASS'
else
  /storage-initializer/scripts/initializer-entrypoint "$MODEL_URI" /mnt/storage/model
  sha256sum -c "${DEMO_CONFIG:-/opt/demo}/model.sha256"
  touch .complete
  sync
  echo 'MODEL_DECRYPT_AND_HASHES_PASS'
fi
# A guest boot ID proves a restart opened the same disk in a new VM.
boot=$(cat /proc/sys/kernel/random/boot_id)
if [ -s /mnt/storage/first-boot ]; then
  first=$(cat /mnt/storage/first-boot)
  printf 'MODEL_REOPEN first_boot=%s current_boot=%s\n' "$first" "$boot"
else
  printf '%s\n' "$boot" > /mnt/storage/first-boot
  sync
  printf 'MODEL_FIRST_BOOT boot=%s\n' "$boot"
fi

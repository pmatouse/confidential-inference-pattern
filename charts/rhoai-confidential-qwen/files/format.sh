#!/bin/bash
set -euo pipefail
# Raw block device only; never erase an existing signature or mismatched LUKS header.
DEVICE=/dev/block-device
fetch_pass() {
  local status line body
  exec 3<>/dev/tcp/127.0.0.1/8006 || return 1
  printf 'GET /cdh/resource/%s HTTP/1.0\r\nHost: localhost\r\n\r\n' "${LUKS_RESOURCE#kbs:///}" >&3
  IFS= read -r status <&3 || return 1
  while IFS= read -r line <&3; do [ "${line%$'\r'}" = '' ] && break; done
  body=$(cat <&3)
  exec 3<&- 3>&-
  [[ "$status" == *' 200 '* ]] && [ -n "$body" ] || return 1
  printf '%s' "$body"
}
PASS=''
for ((i=0; i<90; i++)); do
  if PASS=$(fetch_pass); then break; fi
  sleep 2
done
[ -n "$PASS" ] || { echo 'Attested LUKS key release failed' >&2; exit 1; }
export PASS
if cryptsetup isLuks "$DEVICE"; then
  printf '%s' "$PASS" | cryptsetup --key-file=- luksOpen --test-passphrase "$DEVICE"
  echo 'LUKS_REOPEN_KEY_VERIFIED'
else
  [ -z "$(wipefs --no-act --noheadings --output TYPE "$DEVICE")" ] || { echo 'Refusing to format a device with an existing signature' >&2; exit 1; }
  cmp -n 16777216 "$DEVICE" /dev/zero || { echo 'Refusing to format a nonblank header region' >&2; exit 1; }
  echo 'LUKS_NEW_VOLUME_VERIFIED'
fi
exec /usr/local/bin/luks-helper format-disk

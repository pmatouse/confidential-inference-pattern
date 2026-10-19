#!/bin/bash
set -eu
for ((i=0; i<900; i++)); do
  if [ -s /dev/shm/luks-helper.pid ]; then
    helper_pid=$(cat /dev/shm/luks-helper.pid)
    case "$helper_pid" in ''|*[!0-9]*) exit 1;; esac
    target="/proc/$helper_pid/root/mnt/storage"
    [ -f "$target/.ready" ] && break
  fi
  sleep 1
done
[ -f "${target:?}/.ready" ] || { echo 'Encrypted storage did not become ready' >&2; exit 1; }
# Mount the helper's already-open mapper in this container's mount namespace.
# A symlink through /proc/<pid>/root recurses in Python tarfile's path checks;
# Linux also refuses bind-mounting this cross-namespace proc magic link.
if [ -L /mnt/storage ]; then
  [ "$(readlink /mnt/storage)" = "$target" ] || exit 1
  rm /mnt/storage
fi
mkdir -p /mnt/storage
# The published initializer has Python but no mount(8). This does not unlock
# or format anything: only the stock helper creates the decrypted mapper.
python3 - "/proc/$helper_pid/root/dev/mapper/mapper" <<'PY'
import ctypes, os, sys
if not any(line.split()[4] == '/mnt/storage' for line in open('/proc/self/mountinfo')):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
    libc.mount.restype = ctypes.c_int
    if libc.mount(os.fsencode(sys.argv[1]), b'/mnt/storage', b'xfs', 0, None):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
PY

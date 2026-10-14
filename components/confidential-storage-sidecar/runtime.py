#!/usr/bin/env python3
"""Trusted guest-only storage supervisor. No Kubernetes client or network API."""
import ctypes
import hashlib
import json
import lzma
import os
from pathlib import Path
import resource
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import tomllib

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long
LIBC.mount.argtypes = [ctypes.c_char_p] * 3 + [ctypes.c_ulong, ctypes.c_char_p]
LIBC.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
LIBC.setns.argtypes = [ctypes.c_int, ctypes.c_int]
ROOT = Path("/opt/storage-sidecar")
PRIVATE = Path("/run/confidential-containers")
INITDATA = PRIVATE / "initdata/initdata.toml"
AA_SOCKET = PRIVATE / "attestation-agent/attestation-agent.sock"
CDH_SOCKET = PRIVATE / "cdh.sock"
SERVICE_SOCKET = "/run/coco/storage-service/agent.sock"
STOP = False
ACTIVE_CONSUMER = None


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def storage_diagnostic():
    """Export only the service's fixed labels, never arbitrary child output."""
    path = PRIVATE / "storage.log"
    if not path.is_file():
        return
    with path.open("rb") as stream:
        lines = stream.read(65536).decode(errors="replace").splitlines()
    for line in lines[-16:]:
        if re.fullmatch(
            r"STORAGE_SERVICE denied_state_retained stage=[a-z0-9-]{1,48} "
            r"category=(authority-config|authority-transport|authority-binding|"
            r"private-attestation|authority-receipt|local-or-kbs)",
            line,
        ):
            print(line, flush=True)


def check(result):
    if result < 0:
        raise OSError(ctypes.get_errno(), "guest kernel operation failed")
    return result


def mount(source, target, kind=None, flags=0, data=None):
    check(
        LIBC.mount(
            source.encode() if source else None,
            str(target).encode(),
            kind.encode() if kind else None,
            flags,
            data.encode() if data else None,
        )
    )


def private_file(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data.encode() if isinstance(data, str) else data)


def stock_command(name):
    return [
        str(ROOT / "stock/usr/lib64/ld-linux-x86-64.so.2"),
        "--library-path",
        str(ROOT / "stock/usr/lib64"),
        str(ROOT / "stock/usr/local/bin" / name),
    ]


def start_private(command, name, endpoint):
    log = open(PRIVATE / (name + ".log"), "xb")
    process = subprocess.Popen(
        command,
        stdout=log,
        stderr=log,
        # Stock Kata signals the entire container cgroup on stop. Keep private
        # children alive until the supervisor closes mounts and ownership.
        preexec_fn=lambda: signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}
        ),
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "RUST_LOG": "warn",
            "LD_LIBRARY_PATH": str(ROOT / "stock/usr/lib64"),
            "MKE2FS_CONFIG": str(ROOT / "tools/etc/mke2fs.conf"),
        },
    )
    for _ in range(600):
        require(process.poll() is None, name + " stopped before ready")
        if Path(endpoint).is_socket():
            return process
        time.sleep(0.1)
    raise RuntimeError(name + " startup timeout")


def device_node(path, mode, major, minor):
    path = Path(path)
    path.parent.mkdir(exist_ok=True)
    if not path.exists():
        os.mknod(path, mode | 0o600, os.makedev(major, minor))
    st = path.stat()
    require(
        stat.S_IFMT(st.st_mode) == mode and st.st_rdev == os.makedev(major, minor),
        "wrong guest device",
    )


def initialize_private():
    require(
        os.geteuid() == 0 and os.uname().machine == "x86_64",
        "guest root/x86_64 required",
    )
    require(
        os.uname().release == "6.12.0-211.16.1.el10_2.x86_64", "unapproved guest kernel"
    )
    require(
        "SwapTotal:             0 kB" in Path("/proc/meminfo").read_text(),
        "guest swap enabled",
    )
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    check(LIBC.prctl(4, 0, 0, 0, 0))  # PR_SET_DUMPABLE
    os.umask(0o077)
    require(not PRIVATE.exists(), "private state already exists")
    PRIVATE.mkdir(mode=0o700)
    mount("tmpfs", PRIVATE, "tmpfs", 2 | 4 | 8, "size=32m,mode=0700")
    (PRIVATE / "attestation-agent").mkdir(mode=0o700)
    # This node addresses only the SNP guest kernel. Never a host path/device.
    major, minor = map(
        int, Path("/sys/class/misc/sev-guest/dev").read_text().split(":")
    )
    device_node("/dev/sev-guest", stat.S_IFCHR, major, minor)
    device_node("/dev/mapper/control", stat.S_IFCHR, 10, 236)
    # Privileged helper receives guest devices. Explicitly create missing NVIDIA
    # character nodes from guest sysfs; no host numbers are accepted.
    for dev in Path("/sys/dev/char").iterdir():
        uevent = dev / "uevent"
        if not uevent.exists():
            continue
        fields = dict(
            line.split("=", 1)
            for line in uevent.read_text().splitlines()
            if "=" in line
        )
        name = fields.get("DEVNAME", "")
        if name in ["nvidia0", "nvidiactl", "nvidia-uvm", "nvidia-uvm-tools"]:
            major, minor = map(int, dev.name.split(":"))
            device_node("/dev/" + name, stat.S_IFCHR, major, minor)


def verified_configuration(source):
    with open(source, "rb") as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536, "InitData too large")
    init = tomllib.loads(raw.decode())
    require(
        init["version"] == "0.1.0" and init["algorithm"] == "sha256",
        "unsupported InitData",
    )
    data = init["data"]
    aa = tomllib.loads(data["aa.toml"])
    require(set(aa) == {"token_configs"}, "unapproved AA settings")
    private_file(INITDATA, raw)
    private_file(PRIVATE / "aa.toml", data["aa.toml"])
    # The unchanged SNP AA checks this exact InitData against hardware HOST_DATA
    # BEFORE binding its socket. A substituted ConfigMap cannot pass this check.
    aa_process = start_private(
        stock_command("attestation-agent")
        + ["--config-file", str(PRIVATE / "aa.toml"), "--initdata-toml", str(INITDATA)],
        "aa",
        AA_SOCKET,
    )
    print("SIDECAR_STOCK_AA_INITDATA_PASS", flush=True)
    configuration = json.loads(data["storage-sidecar.json"])
    require(configuration["schemaVersion"] == 1, "unsupported sidecar configuration")
    cdh = tomllib.loads(data["cdh.toml"])
    require(
        cdh.get("credentials") == [] and cdh["kbc"]["name"] == "cc_kbc",
        "unapproved CDH settings",
    )
    private_file(PRIVATE / "cdh.toml", data["cdh.toml"])
    cdh_process = start_private(
        stock_command("confidential-data-hub") + ["-c", str(PRIVATE / "cdh.toml")],
        "cdh",
        CDH_SOCKET,
    )
    # A pod-network REST key/evidence endpoint would undermine private delivery.
    probe = socket.socket()
    probe.settimeout(2)
    require(
        probe.connect_ex(("127.0.0.1", 8006)) != 0, "public guest key API is enabled"
    )
    probe.close()
    print("SIDECAR_STOCK_AA_INITDATA_AND_PRIVATE_CDH_PASS", flush=True)
    return configuration, data, raw, [aa_process, cdh_process]


def load_modules():
    # Request dm-verity/dm-bufio through the unchanged guest kernel first.
    subprocess.run(
        ["/usr/sbin/dmsetup", "targets"], check=True, stdout=subprocess.DEVNULL
    )
    for name in ["dm-bufio", "xor", "async_tx", "async_xor", "dm-integrity"]:
        if Path("/sys/module/" + name.replace("-", "_")).exists():
            continue
        path = (
            ROOT
            / "stock/usr/lib/modules/6.12.0-211.16.1.el10_2.x86_64/kernel/drivers/md/dm-bufio.ko.xz"
            if name == "dm-bufio"
            else ROOT / "tools/modules" / (name + ".ko.xz")
        )
        raw = lzma.decompress(path.read_bytes())
        buffer = ctypes.create_string_buffer(raw)
        check(
            LIBC.syscall(
                ctypes.c_long(175),
                ctypes.cast(buffer, ctypes.c_void_p),
                ctypes.c_ulong(len(raw)),
                ctypes.c_char_p(b""),
            )
        )


def rpc(request):
    raw = json.dumps(request, separators=(",", ":")).encode()
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(180)
        connection.connect(SERVICE_SOCKET)
        connection.sendall(struct.pack(">I", len(raw)) + raw)

        def read(n):
            result = b""
            while len(result) < n:
                part = connection.recv(n - len(result))
                require(part, "storage service disconnected")
                result += part
            return result

        length = struct.unpack(">I", read(4))[0]
        require(0 < length <= 16384, "invalid storage response")
        return json.loads(read(length))


def transport_devices(config):
    devices = []
    for volume in config["volumes"]:
        st = os.stat(volume["transport_path"], follow_symlinks=False)
        require(stat.S_ISBLK(st.st_mode), "missing raw transport")
        major, minor = os.major(st.st_rdev), os.minor(st.st_rdev)
        fields = dict(
            line.split("=", 1)
            for line in Path(f"/sys/dev/block/{major}:{minor}/uevent")
            .read_text()
            .splitlines()
            if "=" in line
        )
        name = fields["DEVNAME"]
        require(
            name.startswith("sd")
            and name[2:].isalpha()
            and name[2:].islower()
            and len(name) <= 5,
            "unsupported guest transport",
        )
        path = "/dev/" + name
        device_node(path, stat.S_IFBLK, major, minor)
        devices.append(
            {
                "binding_id": volume["binding_id"],
                "device_path": path,
                "major": major,
                "minor": minor,
            }
        )
    require(
        len({(d["major"], d["minor"]) for d in devices}) == len(devices),
        "duplicate devices",
    )
    return devices


class Consumer:
    def __init__(self, connection, expected_args):
        self.connection = connection
        pid, uid, gid = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        require(pid > 1 and uid == gid == 1001, "wrong consumer peer")
        self.pid = pid
        self.pidfd = os.pidfd_open(pid)
        self.ns = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        self.root = os.open(
            f"/proc/{pid}/root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        actual = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]
        require(
            actual == [x.encode() for x in expected_args], "wrong consumer entrypoint"
        )
        status = dict(
            line.split(":", 1)
            for line in Path(f"/proc/{pid}/status").read_text().splitlines()
            if ":" in line
        )
        require(
            status["Uid"].split() == ["1001"] * 4
            and int(status["CapEff"].strip(), 16) == 0
            and status["NoNewPrivs"].strip() == "1",
            "privileged consumer",
        )
        require(
            os.fstat(self.ns).st_ino != os.stat("/proc/self/ns/mnt").st_ino,
            "shared helper mount namespace",
        )
        self.mounts = []

    def alive(self):
        return not select.select([self.pidfd], [], [], 0)[0]

    def namespace_processes(self):
        """Pin surviving workers before teardown, including reparented children."""
        result = []
        inode = os.fstat(self.ns).st_ino
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            fd = None
            try:
                if (entry / "ns/mnt").stat().st_ino != inode:
                    continue
                fd = os.pidfd_open(int(entry.name))
                if (entry / "ns/mnt").stat().st_ino == inode:
                    result.append(fd)
                    fd = None
            except (FileNotFoundError, ProcessLookupError):
                pass
            finally:
                if fd is not None:
                    os.close(fd)
        return result

    def signal_namespace(self, sig):
        processes = self.namespace_processes()
        for fd in processes:
            try:
                signal.pidfd_send_signal(fd, sig)
            except ProcessLookupError:
                pass
            finally:
                os.close(fd)
        return bool(processes)

    def transfer(self, mounts, remove=False):
        pid = os.fork()
        if pid == 0:
            try:
                trees = []
                if not remove:
                    require(self.alive(), "consumer exited")
                    for item in mounts:
                        tree = check(
                            LIBC.syscall(
                                ctypes.c_long(428),
                                ctypes.c_int(-100),
                                ctypes.c_char_p(item["source"].encode()),
                                ctypes.c_uint(1 | os.O_CLOEXEC),
                            )
                        )
                        trees.append(tree)
                check(LIBC.setns(self.ns, 0))
                os.fchdir(self.root)
                os.chroot(".")
                os.chdir("/")
                for n, item in enumerate(mounts):
                    path = item["destination"].encode()
                    if remove:
                        check(LIBC.umount2(path, 0))
                    else:
                        check(
                            LIBC.syscall(
                                ctypes.c_long(429),
                                ctypes.c_int(trees[n]),
                                ctypes.c_char_p(b""),
                                ctypes.c_int(-100),
                                ctypes.c_char_p(path),
                                ctypes.c_uint(4),
                            )
                        )
                        os.close(trees[n])
                        mount(
                            None,
                            item["destination"],
                            flags=4096
                            | 32
                            | 2
                            | 4
                            | 8
                            | (1 if item["readonly"] else 0),
                        )
                os._exit(0)
            except BaseException:
                os._exit(1)
        _, status = os.waitpid(pid, 0)
        require(
            os.waitstatus_to_exitcode(status) == 0, "consumer mount operation failed"
        )
        if not remove:
            self.mounts = mounts


def stop(_signal, _frame):
    global STOP
    STOP = True


def main():
    for sig in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(sig, stop)
    probe = sys.argv[1:] == ["--probe-attestation"]
    require(probe or not sys.argv[1:], "unknown mode")
    connection = None
    if not probe:
        # The application owns the GPU resource. Wait until its container has
        # been created (and stock Kata has attached/initialized that GPU) before
        # starting AA, whose additional-attester list is selected at startup.
        os.chmod("/rendezvous", 0o755)
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind("/rendezvous/storage.sock")
            os.chmod("/rendezvous/storage.sock", 0o666)
            listener.listen(1)
            listener.settimeout(300)
            connection, _ = listener.accept()
    initialize_private()
    config, data, raw, processes = verified_configuration(
        "/configuration/initdata.toml"
    )
    if probe:
        # No resource requests, storage keys, or changes to any PVC.
        for p in reversed(processes):
            p.kill()
        return
    require(not sys.argv[1:], "unknown mode")
    service = config["service"]
    policy_sha = hashlib.sha256(data["policy.rego"].encode()).hexdigest()
    service["authority"].update(
        policy_sha256=policy_sha, init_data=hashlib.sha256(raw).hexdigest()
    )
    for volume in service["volumes"]:
        volume["expected"]["policy_sha256"] = policy_sha
    private_file("/etc/confidential-storage/service.json", json.dumps(service))
    for name in ["/run/coco", "/run/coco/storage", "/run/coco/storage-service"]:
        Path(name).mkdir(mode=0o700)
    mount("tmpfs", "/run/coco/storage", "tmpfs", 2 | 4 | 8, "size=32m,mode=0700")
    mount(None, "/run/coco/storage", flags=1 << 18)  # MS_PRIVATE
    load_modules()
    print("SIDECAR_GUEST_STORAGE_MODULES_READY", flush=True)
    processes.append(
        start_private(
            [
                str(ROOT / "stock/usr/lib64/ld-linux-x86-64.so.2"),
                "--library-path",
                str(ROOT / "stock/usr/lib64"),
                str(ROOT / "confidential-storage-service"),
                "--sidecar-parent",
            ],
            "storage",
            SERVICE_SOCKET,
        )
    )
    print("SIDECAR_PRIVATE_STORAGE_SERVICE_READY", flush=True)
    devices = transport_devices(service)
    consumer = Consumer(connection, config["consumerArgs"])
    global ACTIVE_CONSUMER
    ACTIVE_CONSUMER = consumer
    container_id = hashlib.sha256(os.urandom(32)).hexdigest()
    response = rpc(
        {"action": "activate-many", "container_id": container_id, "devices": devices}
    )
    require(response.get("result") == "mounted-many", "storage activation denied")
    consumer.transfer(response["mounts"])
    connection.sendall(b"READY\n")
    connection.close()
    print("SIDECAR_ATTESTED_STORAGE_MOUNTED", flush=True)
    while consumer.alive() and not STOP:
        require(all(p.poll() is None for p in processes), "private child stopped")
        time.sleep(0.5)
    print("SIDECAR_STOPPING_CONSUMER", flush=True)
    for _ in range(120):
        if not consumer.signal_namespace(signal.SIGTERM):
            break
        time.sleep(0.5)
    require(
        not consumer.signal_namespace(signal.SIGKILL),
        "consumer workers have not exited; ownership retained",
    )
    consumer.transfer(consumer.mounts, remove=True)
    print("SIDECAR_CONSUMER_MOUNTS_REMOVED", flush=True)
    require(
        rpc({"action": "close", "container_id": container_id}).get("result")
        == "closed",
        "storage close denied; ownership retained",
    )
    print("SIDECAR_STORAGE_CLOSED", flush=True)
    for p in reversed(processes):
        p.kill()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Fail stop the application if its trusted storage supervisor fails.
        # Never release authority ownership after an uncertain close.
        if ACTIVE_CONSUMER is not None:
            try:
                ACTIVE_CONSUMER.signal_namespace(signal.SIGKILL)
            except ProcessLookupError:
                pass
        storage_diagnostic()
        # Fixed local diagnostic labels only. Child logs remain root-private.
        print(
            "SIDECAR_FAILED: "
            + (str(error) if isinstance(error, RuntimeError) else type(error).__name__),
            flush=True,
        )
        raise SystemExit(1) from None

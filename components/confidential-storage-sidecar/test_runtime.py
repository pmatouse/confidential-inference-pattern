"""Regression for stock Kata's container-wide stop signal."""

import importlib.util
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "linux", "guest supervisor requires Linux")
class PrivateProcessTests(unittest.TestCase):
    def test_child_survives_cgroup_sigterm_until_explicit_cleanup(self):
        spec = importlib.util.spec_from_file_location(
            "sidecar_runtime", Path(__file__).with_name("runtime.py")
        )
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        with tempfile.TemporaryDirectory() as directory:
            runtime.PRIVATE = Path(directory)
            endpoint = str(Path(directory) / "child.sock")
            child = runtime.start_private(
                [
                    sys.executable,
                    "-c",
                    "import socket,sys; s=socket.socket(socket.AF_UNIX); "
                    "s.bind(sys.argv[1]); s.listen(1); c,_=s.accept(); "
                    "c.sendall(c.recv(8)); c.close()",
                    endpoint,
                ],
                "test",
                endpoint,
            )
            try:
                os.kill(child.pid, signal.SIGTERM)
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(5)
                    client.connect(endpoint)
                    client.sendall(b"cleanup")
                    self.assertEqual(client.recv(8), b"cleanup")
                self.assertEqual(child.wait(timeout=5), 0)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()

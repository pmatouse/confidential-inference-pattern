"""Startup must reject incomplete authority packages before binding a socket."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import serve


class PackagingTests(unittest.TestCase):
    def test_packaged_profiles_parse(self):
        serve.require_storage_profiles()

    def test_missing_profile_fails_before_reading_server_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(serve, "RO_PROFILE", Path(directory) / "absent.json"):
                with self.assertRaises(FileNotFoundError):
                    serve.configured_server("never-opened-server-config.json")


if __name__ == "__main__":
    unittest.main()

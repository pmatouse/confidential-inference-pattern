"""Versioned destinations must not silently reinterpret legacy approvals."""

import unittest
from storage_profiles import destination, profile_digest, supports


class ProfileTests(unittest.TestCase):
    def test_v1_destinations_remain_fixed(self):
        for mode, stem, path in [
            ("ro", "ro-luks2-verity", "/models"),
            ("rw", "rw-luks2", "/data"),
        ]:
            digest = profile_digest(stem + "-v1")
            self.assertTrue(supports(mode, digest, path))
            self.assertFalse(supports(mode, digest, path + "/another"))

    def test_v2_requires_known_profile_and_safe_authenticated_path(self):
        for mode, stem in [("ro", "ro-luks2-verity"), ("rw", "rw-luks2")]:
            digest = profile_digest(stem + "-v2")
            for path in ["/models/qwen", "/models/embedding", "/data", "/checkpoints"]:
                self.assertTrue(supports(mode, digest, path))
            self.assertFalse(supports(mode, "a" * 64, "/data"))
            self.assertFalse(supports("other", digest, "/data"))
        for path in [
            None,
            "/",
            "/proc/x",
            "/dev/x",
            "/data/../x",
            "/data//x",
            "/data/",
            "/data/é",
        ]:
            self.assertFalse(destination(path))

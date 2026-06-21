import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from netsudo.config import load_config


class ConfigTests(unittest.TestCase):
    def write_config(self, body: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "netsudo.toml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_loads_profile_and_renders_policy(self):
        path = self.write_config(
            """
            [pfsense]
            host = "192.168.3.1"

            [profiles.admin]
            interfaces = ["lan"]
            destinations = ["192.168.3.0/24"]
            protocol = "tcp"
            ports = ["22", "443"]
            max_duration = "20m"
            """
        )

        config = load_config(str(path))
        self.assertEqual(config.pfsense.user, "admin")
        self.assertEqual(config.pfsense.backend, "ssh")
        self.assertTrue(config.pfsense.batch_mode)
        self.assertEqual(config.profiles["admin"].source_alias, "NETSUDO_ADMIN_SRC")

        policy = json.loads(config.policy_json())
        self.assertEqual(policy["profiles"]["admin"]["ports"], ["22", "443"])
        self.assertEqual(policy["profiles"]["admin"]["max_seconds"], 1200)

    def test_rejects_invalid_destination(self):
        path = self.write_config(
            """
            [pfsense]
            host = "192.168.3.1"

            [profiles.bad]
            interfaces = ["lan"]
            destinations = ["not-a-network"]
            """
        )

        with self.assertRaises(ValueError):
            load_config(str(path))

    def test_rejects_too_long_alias(self):
        path = self.write_config(
            """
            [pfsense]
            host = "192.168.3.1"

            [profiles.bad]
            interfaces = ["lan"]
            destinations = ["192.168.3.0/24"]
            source_alias = "NETSUDO_ALIAS_NAME_THAT_IS_TOO_LONG"
            """
        )

        with self.assertRaises(ValueError):
            load_config(str(path))

    def test_parses_password_prompt_bootstrap_settings(self):
        path = self.write_config(
            """
            [pfsense]
            host = "192.168.3.1"
            backend = "ssh"
            batch_mode = false
            identity_file = "/home/user/.ssh/netsudo_pfsense"

            [profiles.admin]
            interfaces = ["lan"]
            destinations = ["192.168.3.0/24"]
            """
        )

        config = load_config(str(path))
        self.assertFalse(config.pfsense.batch_mode)
        self.assertEqual(config.pfsense.identity_file, "/home/user/.ssh/netsudo_pfsense")

    def test_rejects_unknown_backend(self):
        path = self.write_config(
            """
            [pfsense]
            host = "192.168.3.1"
            backend = "telnet"

            [profiles.admin]
            interfaces = ["lan"]
            destinations = ["192.168.3.0/24"]
            """
        )

        with self.assertRaises(ValueError):
            load_config(str(path))


if __name__ == "__main__":
    unittest.main()

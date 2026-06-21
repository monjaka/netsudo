import contextlib
import io
import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from netsudo.cli import main


class CliTests(unittest.TestCase):
    def write_config(self, body: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "netsudo.toml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_privileged_allow_reruns_through_sudo(self):
        path = self.write_config(
            """
            [pfsense]
            host = "192.168.3.1"

            [defaults]
            confirm = false

            [profiles.admin]
            interfaces = ["lan"]
            destinations = ["192.168.115.0/24"]
            require_sudo = true
            """
        )

        with mock.patch("os.geteuid", return_value=1000), \
                mock.patch("shutil.which", return_value="/usr/bin/sudo"), \
                mock.patch("subprocess.call", return_value=0) as call:
            result = main(
                [
                    "allow",
                    "admin",
                    "--source",
                    "192.168.6.60",
                    "--destination",
                    "192.168.115.100",
                    "--for",
                    "20m",
                    "--reason",
                    "check Wazuh",
                    "--config",
                    str(path),
                ]
            )

        self.assertEqual(result, 0)
        command = call.call_args.args[0]
        self.assertEqual(command[:2], ["/usr/bin/sudo", "env"])
        self.assertIn("NETSUDO_SUDO_REEXEC=1", command)
        self.assertIn("-m", command)
        self.assertIn("netsudo.cli", command)
        self.assertEqual(command[-2:], ["--config", str(path.resolve())])

    def test_sudo_reexec_guard_returns_error(self):
        path = self.write_config(
            """
            [pfsense]
            host = "192.168.3.1"

            [profiles.admin]
            interfaces = ["lan"]
            destinations = ["192.168.115.0/24"]
            require_sudo = true
            """
        )

        with mock.patch("os.geteuid", return_value=1000), \
                mock.patch.dict(os.environ, {"NETSUDO_SUDO_REEXEC": "1"}), \
                contextlib.redirect_stderr(io.StringIO()):
            result = main(["allow", "admin", "--config", str(path)])

        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()

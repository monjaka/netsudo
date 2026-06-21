import contextlib
import io
import unittest

from netsudo.installer import (
    build_uninstall_remote_command,
    main,
    render_config,
    restricted_authorized_key_line,
    restricted_wrapper_script,
)


class InstallerTests(unittest.TestCase):
    def test_render_config_includes_identity_and_batch_mode(self):
        rendered = render_config(
            host="192.168.3.1",
            user="admin",
            backend="ssh",
            identity_file="/home/user/.ssh/netsudo_pfsense",
            batch_mode=False,
        )

        self.assertIn('identity_file = "/home/user/.ssh/netsudo_pfsense"', rendered)
        self.assertIn("batch_mode = false", rendered)
        self.assertIn('backend = "ssh"', rendered)

    def test_restricted_authorized_key_line_forces_wrapper(self):
        public_key = "ssh-ed25519 AAAATESTKEY netsudo-pfsense"
        line = restricted_authorized_key_line(public_key, wrapper_path="/usr/local/sbin/netsudo-ssh-wrapper.sh")

        self.assertIn('command="/usr/local/sbin/netsudo-ssh-wrapper.sh"', line)
        self.assertIn("no-port-forwarding", line)
        self.assertIn("no-pty", line)
        self.assertTrue(line.endswith(public_key))

    def test_restricted_wrapper_allows_helper_actions_only(self):
        wrapper = restricted_wrapper_script("/usr/local/sbin/netsudo-helper.php")

        self.assertIn("SSH_ORIGINAL_COMMAND", wrapper)
        self.assertIn("exec \"$php\" \"$helper\" grant", wrapper)
        self.assertIn("exec \"$php\" \"$helper\" status", wrapper)
        self.assertNotIn("install-helper", wrapper)

    def test_uninstall_remote_command_removes_helper_and_key(self):
        command = build_uninstall_remote_command(
            helper="/usr/local/sbin/netsudo-helper.php",
            wrapper="/usr/local/sbin/netsudo-ssh-wrapper.sh",
            key_blob="AAAATESTKEY",
        )

        self.assertIn("rm -f '/usr/local/sbin/netsudo-helper.php'", command)
        self.assertIn("rm -f '/usr/local/sbin/netsudo-ssh-wrapper.sh'", command)
        self.assertIn("authorized_keys", command)
        self.assertIn("AAAATESTKEY", command)

    def test_keep_flags_require_uninstall(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--keep-config", "--non-interactive"]), 1)


if __name__ == "__main__":
    unittest.main()

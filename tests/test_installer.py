import unittest

from netsudo.installer import render_config


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


if __name__ == "__main__":
    unittest.main()

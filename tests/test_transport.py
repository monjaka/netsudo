import unittest

from netsudo.config import PfSenseConfig
from netsudo.transport import TransportError, ssh_base


class TransportTests(unittest.TestCase):
    def test_ssh_batch_mode_can_be_disabled_for_bootstrap(self):
        config = PfSenseConfig(
            host="192.168.3.1",
            user="admin",
            helper="/usr/local/sbin/netsudo-helper.php",
            batch_mode=False,
        )

        self.assertIn("BatchMode=no", ssh_base(config))

    def test_rest_backend_fails_clearly_until_implemented(self):
        config = PfSenseConfig(
            host="192.168.3.1",
            user="admin",
            helper="/usr/local/sbin/netsudo-helper.php",
            backend="rest",
        )

        with self.assertRaises(TransportError):
            ssh_base(config)


if __name__ == "__main__":
    unittest.main()

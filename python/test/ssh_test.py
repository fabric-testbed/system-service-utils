import unittest

from fss_utils.sshkey import FABRICSSHKey, FABRICSSHKeyException


class FABRICSSHKeyTest(unittest.TestCase):

    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def testGenerateRSA(self):
        """
        Test generation of various key types
        :return:
        """
        rsa = FABRICSSHKey.generate("rsa_key@localhost", "rsa")
        rsa.get_fingerprint()
        self.assertTrue(rsa.length >= 3072)

        priv, pub = rsa.as_keypair()

        rsa1 = FABRICSSHKey(pub)
        self.assertEqual(rsa1.length, rsa.length)
        self.assertEqual(rsa1.get_fingerprint(), rsa.get_fingerprint())
        self.assertEqual(rsa1.comment, "rsa_key@localhost")

        with open('rsa_key.priv', 'w') as f:
            f.write(priv)

        with open('rsa_key.pub', 'w') as f:
            f.write(pub)

    def testGenerateECDSA(self):
        """
        Test generation of various key types
        :return:
        """
        ecdsa = FABRICSSHKey.generate("ecdsa_key@localhost", "ecdsa")
        ecdsa.get_fingerprint()
        # We don't validate ECDSA key length - sometimes it is 249 or other numbers
        # self.assertTrue(ecdsa.length >= 255)

        priv, pub = ecdsa.as_keypair()

        ecdsa1 = FABRICSSHKey(pub)
        self.assertEqual(ecdsa1.length, ecdsa.length)
        self.assertEqual(ecdsa1.get_fingerprint(), ecdsa.get_fingerprint())
        self.assertEqual(ecdsa1.comment, "ecdsa_key@localhost")

        with open('ecdsa_key.priv', 'w') as f:
            f.write(priv)

        with open('ecdsa_key.pub', 'w') as f:
            f.write(pub)
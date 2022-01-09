import unittest

from fss_utils.sshkey import FABRICSSHKey, FABRICSSHKeyException

# DSA key
DSA_PUB = "ssh-dss AAAAB3NzaC1kc3MAAACBAK/4FuN+USXlTb+176MxU9xwWUby+5eVUuAS3P6sfsSDzNyHEKXb+yZtdXGr+hpaePIhXg93sgCF" \
          "dGTMHOO7U/ltYq5cjBYSTw2k6/X+5sT1M+9kM6vmWOyV51VJkB+kajM9Eu5xoE9RXIV3gKu7Yoi9ADeMbnxUG2sQ9+MJSs4bAAAAFQCr" \
          "0iOxPqH6OwNqQ7BCnGiiTum/vQAAAIEAr2WuLkhrQWaMU7y7vGBNzcFmYApotNH3OUvnC3NyWHdbHaUrUt43rIH/w0caUdE8sOrGuCVk" \
          "LtMLrkllHGJgGtgHLe9NjfAwluewS7wB7WT4FdhuvSaVpHj5gwV18GOIzZ+yvZIKva5hhjGI/dDBjP8plAs3xMDnKQH9mNoLAGoAAACA" \
          "PDmzz/3sxXMyJnJFQBcN1hCPA5Y9SnmmpANimTaZW2lqozxxi1Sm/sTqAop94F2wLdVgIhCkDS0ifWn4G2UPlyRMw+ossc22YnRnWYWI" \
          "6LxexJDp4qEvYpT+QfbUlAv8j725aDaeu62Lka3sOgfukC+9s7HiH0+xGJltXT3FXSI= " \
          "user@laptop.domain"

# 1024bit key
RSA_PUB_1024 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDILd1tQaj1SzfmJvhHL7DZCs8banXiudOyLYG59XuPIkSy49D4Bd07yjlgyH" \
                "/9vuLop/EuhXnFf/VA6fi076ja2/I16aYMuu+b3S+jv0XisfnAl3myte+la/z2xKJ3U4zu05FiicM6f8kWIPKHkjnm0Xw1Y6BL" \
                "tYNAs1aikArhrQ== user@laptop.domain"

# 3072bit key
RSA_PUB_3072 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCsZlZXj64xaft9lZQOaFB7lxrrpaNlqHVekP5iVCxYT5Wu/1nrQxZoT+oJT9" \
               "WUFEK/TO/fgTmo0eZclmH1lUWinK2V3WO5uux0cn8hsMQVgJHzb3yp+t2TuXGCSIIUTyFH/ABl9Rh+FZZ3BiGLBN+eUVzAkYWu" \
               "kdeUbWydWO5l88/heuhyw7wnCaZgiP3v2Z4DQNfeVm4B1Ykd+kk1t+TMRnSXk/DjKVuUhLoaSS4Upo9IlRNgUjYKZ+iQF5gX4z" \
               "o8fyLZZiVeTVw9I6K1YothjgFQKmOhn/8EZKyPxo99R3ROwbq4N2MQn+JlopWRaZ60/6jZKlKWY6a/OYUCX44qBSQwhraKtKng" \
               "jo2PhyMwLp7ln7M+7u6sUAPNYcGoEsOcP/iHSpHd9lW7xpFsN/y+wS4UUkfHun+gwj9xnW1mh8GxWzbb/UAq/1iJ85dfxFsFL0" \
               "OwD8Exgbpr5YVAbrgRfEvHsgFvDhLHmSi4N746P7StLXbNOtcAHRBR2HvgXsE= " \
               "user@laptop.domain"


# 4096bit RSA
RSA_PUB_4096 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDPP7HUyL64I8XUUTEba5TomJ+tc2AvKATDRud5HAT44SevwmiEEfLei8Cc/L" \
                "CeDPdumS3fqKNNBwwgFT/wOd1QT4bLor/trOTzd8zFrh1cwpMu6eBh8iXmesa+pNZK/9XDeiIgVJpcIF+YRefgfgHUO5Fl5bIp" \
                "BgfXbMB7nG4Y+3bO1PLzt3Mf89UseW0CgqTNqpYXb00MnG5TIy46KrDY/UXRgS47IE1oFNTXV8yY5mSjWGsWIryUtY1OtZXRI6" \
                "xJ5UVRguD8cvAtZOaqhOpZ+ROUgsMSQj1fdCx3QizpYFoD0Ym8tBK+L9XmVmUsMiYRwgycBmVTHMi/B0yI08cJuCtGP65d1vJi" \
                "cVkkqk9wKebXBwG3t9n97iZTE3lwYLUo6qGMrYVmB5emZ9bOkpSEYwUIgzm1k8+yX+U2qVPg5om8lrhK21wETT7SCoti7UZ+lu" \
                "dnq1KQONzm0lTX0S+etrozgjmlhKo58Ge49yZLak2K4sjPG+fS9zRFH+vDoJQefmMi9P4EaIjR0yj6edDWnRMM/UsZYJIUmpMb" \
                "E/VKBDkH/MkrwbqSOSpkbaDiYEd2FjVx6ueCtQgdTrtI8WOqtT0UKJodRjqIxbj41w+IRZ5SmwUlqixjH82s3HE6DhNXbfZjDA" \
                "0KcTOqunTkIIpTgg8x4V1oNSwXG6BXu/Dew== user@laptop.domain"

# 256bit ECDSA
ECDSA_PUB_256 = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD7AvTCiMzXhNbTjjTvlsvMmDN" \
                "ZkZzQqTKxzrt+e/DdjpCXuM3YuQrUjo+CceGD5Ch3/Qx6HJT42sw/YpmtZzOA= " \
                "user@laptop.domain"

# 384bit ECDSA
ECDSA_PUB_384 = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBE5WeENby87y7MMdAaFGI95DlE" \
                "Ez0bKOlwrNp156tcXYT9P0GrgGMPy24bOoq6YGAwrg8WRvmd5dhgs9yrEJRgF3F7sqzwi2Ymhwft7E3gJXRRQwX4JJFscXRt49" \
                "2T959w== user@laptop.domain"

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

    def testDSA(self):
        with self.assertRaises(FABRICSSHKeyException) as e:
            FABRICSSHKey(DSA_PUB)

    def testShortRSA(self):
        with self.assertRaises(FABRICSSHKeyException) as e:
            FABRICSSHKey(RSA_PUB_1024)

    def testValidRSA(self):
        rsak = FABRICSSHKey(RSA_PUB_3072)
        rsak1 = FABRICSSHKey(RSA_PUB_3072)
        self.assertTrue(rsak == rsak1)
        self.assertEqual(rsak.length, 3072)
        # compared to ssh-keygen -lf <file> -E md5
        self.assertEqual(rsak.get_fingerprint(), "MD5:14:68:04:d5:8a:f7:03:1b:a5:14:26:62:77:d8:15:4e")
        self.assertEqual(rsak.get_fingerprint(kind='sha256'), "SHA256:Yz9kfDC5d/1C6nafo/hFDZOCW9FydbZGEo9B/g2V9Zk")
        self.assertEqual(rsak.comment, "user@laptop.domain")

    def testValidRSA1(self):
        rsak = FABRICSSHKey(RSA_PUB_3072, "altcomment")
        self.assertEqual(rsak.length, 3072)
        # compared to ssh-keygen -lf <file> -E md5
        self.assertEqual(rsak.get_fingerprint(), "MD5:14:68:04:d5:8a:f7:03:1b:a5:14:26:62:77:d8:15:4e")
        self.assertEqual(rsak.get_fingerprint(kind='sha256'), "SHA256:Yz9kfDC5d/1C6nafo/hFDZOCW9FydbZGEo9B/g2V9Zk")
        self.assertEqual(rsak.comment, "altcomment")

    def testValidECDSA(self):
        ecdsak = FABRICSSHKey(ECDSA_PUB_256)
        ecdsak1 = FABRICSSHKey(ECDSA_PUB_256)
        ecdsak2 = FABRICSSHKey(ECDSA_PUB_384)
        self.assertTrue(ecdsak == ecdsak1)
        self.assertFalse(ecdsak == ecdsak2)
        self.assertEqual(ecdsak.length, 256)
        self.assertEqual(ecdsak.get_fingerprint(), "MD5:ed:6f:f4:0d:09:5b:80:d9:f4:16:ab:71:d1:b5:76:a3")
        self.assertEqual(ecdsak.get_fingerprint(kind='sha256'), "SHA256:YUoqrMjtU0kOtvvCe3jumvaf2wmEV+N8LjGT16fRu3I")

    def testValidECDSA1(self):
        ecdsak = FABRICSSHKey(ECDSA_PUB_384)
        self.assertEqual(ecdsak.length, 384)
        self.assertEqual(ecdsak.get_fingerprint(), "MD5:05:89:60:01:c4:59:76:83:58:ad:62:1b:0e:33:ab:81")
        self.assertEqual(ecdsak.get_fingerprint(kind='sha256'), "SHA256:6EwJWq36+j6KRNIMGoO48YUhIC3CRAVfGNeBFXn7XS0")
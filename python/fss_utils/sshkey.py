#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2020 FABRIC Testbed
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
# Author: Ilya Baldin (ibaldin@renci.org) Michael Stealey (stealey@renci.org)

from typing import Tuple
import re
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# this is how we set what key type is produced by default and default key length
KEY_ALGORITHMS = {
    "rsa": (rsa.generate_private_key(public_exponent=65537, key_size=3072), 3072),
    "ecdsa": (ec.generate_private_key(ec.SECP256R1()), 256)
}

LABEL_REGEX = "^[a-zA-Z0-9@-_()]{0,64}$"


class FABRICSSHKey:

    def __init__(self, public_key: str):
        """
        Load the public portion of the key
        """
        assert public_key is not None
        # this also validates that this is either DSA or ECDSA key
        self._length = FABRICSSHKey.get_key_length(public_key, validate=True)
        self._name, self._public_key, self._label = public_key.split(" ")
        # can only be generated
        self._private_key = None

    @property
    def name(self):
        return self._name

    @property
    def public_key(self):
        return self._public_key

    @property
    def label(self):
        return self._label

    @property
    def length(self):
        return self._length

    @property
    def private_key(self):
        return self._private_key

    @classmethod
    def generate(cls, label: str, algorithm: str):
        assert label is not None
        matches = re.match(LABEL_REGEX, label)
        if matches is None:
            raise FABRICSSHKeyException(f'Label {label} does not match expected regular expression {LABEL_REGEX}')
        # generate a key
        if algorithm not in KEY_ALGORITHMS.keys():
            raise FABRICSSHKeyException(f'Key Algorithm configured as {algorithm} is not supported')
        # this calls to generate
        key = KEY_ALGORITHMS[algorithm][0]

        # get the private key in PEM format
        private_key = key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.OpenSSH,
                                        encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
        public_key_with_name = key.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                             format=serialization.PublicFormat.OpenSSH).decode('utf-8')

        # just append the label
        ret = FABRICSSHKey(" ".join([public_key_with_name.strip(),
                                     label]))
        ret._private_key = private_key
        return ret

    def as_keypair(self) -> Tuple[str, str]:
        """
        Returns a typle of private, public keys formatted for SSH
        :return:
        """
        return self.private_key, self.as_public_key_string()

    def as_public_key_string(self):
        return " ".join([self._name, self._public_key, self._label])

    def get_fingerprint(self) -> str:
        """
        Generate MD5 fingerprint. Use 'ssh-keygen -lf <filename> -E md5' to get the same output
        """
        # for some reason Paramiko fingerprint() does not match the output of sshkeygen -lf <key> -E md5
        # so we are rolling our own based on
        # https://stackoverflow.com/questions/64733471/how-to-calculate-a-fingerprint-from-an-rsa-public-key
        rawdata = base64.b64decode(self._public_key)
        hexdigest = hashlib.md5(rawdata).hexdigest()
        keychunks = [hexdigest[i:i+2] for i in range(0, len(hexdigest), 2)]
        return 'MD5:' + ":".join(keychunks)

    @staticmethod
    def get_key_length(ks: str, validate=False) -> int:
        """
        Returns key length of the ECC or DSA public key using horrible non-portable hacks.
        Validates the key format first by loading it as DSA or ECDSA.
        """
        try:
            ck = serialization.load_ssh_public_key(ks.encode('utf-8'))
        except:
            raise FABRICSSHKeyException(f'Provided public key starting with {ks[0:50]} cannot be imported')

        return ck.key_size

    def __str__(self):
        return f"Private:\n{self.private_key}\nPublic:\n{' '.join([self._name, self._public_key, self._label])}"

    def __repr__(self):
        return str(self)


class FABRICSSHKeyException(Exception):
    def __init__(self, msg: str):
        assert msg is not None
        super().__init__(f"SSH Key exception: {msg}")
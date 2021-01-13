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
# Author Komal Thareja (kthare10@renci.org)
import unittest

from fss_utils.jwt_manager import JWTManager, ValidateCode


class JWTManagerTest(unittest.TestCase):
    def test_encode_and_sign_with_private_key_file_does_not_exist(self):
        claims = {"foo": "bar"}
        code, exception = JWTManager.encode_and_sign_with_private_key(validity=90, claims=claims,
                                                                      private_key_file_name="abc.pem",
                                                                      kid="abcd-kid", algorithm="RS256")
        self.assertEqual(code, ValidateCode.UNABLE_TO_LOAD_KEYS)
        self.assertIsNotNone(exception)
        self.assertTrue(isinstance(exception, Exception))
        self.assertFalse(isinstance(exception, str))

    def test_encode_and_sign_with_valid_key_no_passphrase(self):
        claims = {"foo": "bar"}
        code, token = JWTManager.encode_and_sign_with_private_key(validity=90, claims=claims,
                                                                  private_key_file_name="test/data/privkey.pem",
                                                                  kid="abcd-kid", algorithm="RS256")
        self.assertEqual(code, ValidateCode.VALID)
        self.assertIsNotNone(token)
        self.assertFalse(isinstance(token, Exception))
        self.assertTrue(isinstance(token, str))

        code, decoded_token = JWTManager.decode(cookie=token, verify=False, compression=False)

        self.assertEqual(code, ValidateCode.VALID)
        for key, value in claims.items():
            self.assertIsNotNone(decoded_token.get(key), value)

    def test_encode_jwk_with_non_existent_pem(self):
        code, exception = JWTManager.encode_jwk(key_file_name="abc.pem", kid="kid", alg="RS256")
        self.assertEqual(code, ValidateCode.UNABLE_TO_LOAD_KEYS)
        self.assertIsNotNone(exception)
        self.assertTrue(isinstance(exception, Exception))
        self.assertFalse(isinstance(exception, str))

    def test_encode_jwk_with_valid_pem(self):
        code, token = JWTManager.encode_jwk(key_file_name="test/data/pubkey.pem", kid="kid", alg="RS256")
        self.assertEqual(code, ValidateCode.VALID)
        self.assertIsNotNone(token)
        self.assertFalse(isinstance(token, Exception))
        self.assertTrue(isinstance(token, dict))

    def test_encode_and_compress_enabled(self):
        claims = {"foo": "bar"}
        code, token = JWTManager.encode_and_compress(claims=claims, secret="super-secret", validity=500)
        self.assertEqual(code, ValidateCode.VALID)

        code, decoded_token = JWTManager.decode(cookie=token, verify=False, compression=True)

        self.assertEqual(code, ValidateCode.VALID)
        for key, value in claims.items():
            self.assertIsNotNone(decoded_token.get(key), value)

    def test_encode_and_compress_disabled(self):
        claims = {"foo": "bar"}
        code, token = JWTManager.encode_and_compress(claims=claims, secret="super-secret", validity=500,
                                                     compression=False)
        self.assertEqual(code, ValidateCode.VALID)

        code, decoded_token = JWTManager.decode(cookie=token, verify=False, compression=False)

        self.assertEqual(code, ValidateCode.VALID)
        for key, value in claims.items():
            self.assertIsNotNone(decoded_token.get(key), value)

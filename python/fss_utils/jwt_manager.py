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
import base64
import enum
import gzip
import traceback
from datetime import timedelta, datetime
from typing import Tuple, Union

import jwt
from authlib.jose import jwk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


@enum.unique
class ValidateCode(enum.Enum):
    VALID = 1
    UNSPECIFIED_KEY = 2
    UNSPECIFIED_ALG = 3
    UNKNOWN_KEY = 4
    INVALID = 5
    UNABLE_TO_FETCH_KEYS = 6
    UNPARSABLE_TOKEN = 7
    UNABLE_TO_DECODE_KEYS = 8
    UNABLE_TO_LOAD_KEYS = 9
    UNABLE_TO_COMPRESS = 10
    UNABLE_TO_DECOMPRESS = 11
    UNSPECIFIED_ID_TOKEN = 12

    def interpret(self, exception=None):
        interpretations = {
            1: "Token is valid",
            2: "Token does not specify key ID",
            3: "Token does not specify algorithm",
            4: "Unable to find public key at JWK endpoint",
            5: "Token signature is invalid",
            6: "Unable to fetch keys from the endpoint",
            7: "Unable to parse token",
            8: "Unable to decode public keys",
            9: "Unable to load key from file",
            10: "Unable to compress the encoded token",
            11: "Unable to decompress the encoded token",
            12: "Identity Token or Identity Claims not specified"
          }
        if exception is None:
            return interpretations[self.value]
        else:
            return str(exception) + ". " + interpretations[self.value]


class JWTManager:
    @staticmethod
    def encode_and_sign_with_private_key(*, validity: int, claims: dict, private_key_file_name: str, kid: str,
                                         algorithm: str,
                                         pass_phrase: str = None) -> Tuple[ValidateCode, Union[Exception, str]]:
        """
        sign and base64 encode the token
        :param validity validity in seconds
        :param claims claims to be added in token
        :param private_key_file_name private key file name used to sign the token
        :param kid kid to be added to the header
        :param algorithm algorithm by which to encode the token
        :param pass_phrase private key pass phrase

        :return ValidateCode or None, exception or None, Encoded Token or None:
        """
        if pass_phrase is not None and pass_phrase != "":
            pass_phrase = pass_phrase.encode("utf-8")
        else:
            pass_phrase = None

        try:
            with open(private_key_file_name) as private_key_fh:
                pem_data = private_key_fh.read()
                private_key_fh.close()
                private_key = serialization.load_pem_private_key(data=pem_data.encode("utf-8"),
                                                                 password=pass_phrase,
                                                                 backend=default_backend())
        except Exception as e:
            return ValidateCode.UNABLE_TO_LOAD_KEYS, e

        claims['iat'] = int(datetime.now().timestamp())
        claims['exp'] = int((datetime.now() + timedelta(seconds=int(validity))).timestamp())

        try:
            encoded_token = str(jwt.encode(claims, private_key, algorithm=algorithm, headers={'kid': kid}), 'utf-8')
            return ValidateCode.VALID, encoded_token
        except Exception as e:
            return ValidateCode.INVALID, e

    @staticmethod
    def encode_jwk(*, key_file_name: str, kid: str, alg: str) -> Tuple[ValidateCode, Union[Exception, dict]]:
        """
        Encode JWK from a PEM file
        :param key_file_name Key File Name
        :param kid kid to be added to the JWK
        :param alg algorithm to be added

        :return ValidateCode or None, exception or None, JWK or None:
        """
        pem_data = None
        try:
            with open(key_file_name) as public_key_fh:
                pem_data = public_key_fh.read()
                public_key_fh.close()
        except Exception as e:
            return ValidateCode.UNABLE_TO_LOAD_KEYS, e

        try:
            result = jwk.dumps(pem_data, kty='RSA')
            result["kid"] = kid
            result["alg"] = alg
            result["use"] = "sig"
            return ValidateCode.VALID, result
        except Exception as e:
            return ValidateCode.INVALID, e

    @staticmethod
    def encode_and_compress(*, claims: dict, secret: str, validity: int, algorithm: str = 'HS256',
                            compression: bool = True) -> Tuple[ValidateCode, Union[Exception, str]]:
        """
        Encode a JWT
        :claims incoming claims
        :secret secret
        :validity validity in seconds
        :algorithm algorithm
        :compression compression

        :return ValidateCode or None, exception or None, encoded token or None:
        """
        if validity is not None:
            claims['exp'] = int((datetime.now() + timedelta(seconds=int(validity))).timestamp())

        encoded_cookie = None
        try:
            encoded_cookie = jwt.encode(claims, secret, algorithm=algorithm)
        except Exception as e:
            return ValidateCode.INVALID, e

        try:
            if compression:
                compressed_cookie = gzip.compress(encoded_cookie)
                encoded_cookie = base64.urlsafe_b64encode(compressed_cookie)
            encoded_cookie = str(encoded_cookie, 'utf-8')
        except Exception as e:
            return ValidateCode.UNABLE_TO_COMPRESS, e

        return ValidateCode.VALID, encoded_cookie

    @staticmethod
    def decode(*, cookie: str, secret: str = '', verify: bool = True,
               compression: bool = False) -> Tuple[ValidateCode, Union[Exception, dict]]:
        """
        Decode and validate a JWT
        :cookie incoming cookie
        :secret secret
        :compression compression

        :return ValidateCode or None, exception or None, Decoded Token or None:
        """
        try:
            if compression:
                decoded_64 = base64.urlsafe_b64decode(cookie)
                uncompressed_cookie = gzip.decompress(decoded_64)
                cookie = uncompressed_cookie
        except Exception as e:
            traceback.print_exc()
            return ValidateCode.UNABLE_TO_DECOMPRESS, e

        algorithm = None
        try:
            algorithm = jwt.get_unverified_header(cookie).get('alg', None)
        except jwt.DecodeError as e:
            traceback.print_exc()
            return ValidateCode.UNPARSABLE_TOKEN, e

        if algorithm is None:
            return ValidateCode.UNSPECIFIED_ALG, None

        try:
            decoded_token = jwt.decode(cookie, secret, algorithms=[algorithm], verify=verify)
            return ValidateCode.VALID, decoded_token
        except Exception as e:
            traceback.print_exc()
            return ValidateCode.INVALID, e

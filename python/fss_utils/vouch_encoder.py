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
from enum import Enum
from typing import Set, List, Tuple, Union

from .jwt_manager import JWTManager, ValidateCode


class CustomClaimsType(Enum):
    """
    Defines the Custom Claims Types
    """
    OPENID = 1
    EMAIL = 2
    PROFILE = 3
    CILOGON_USER_INFO = 4

    def interpret(self) -> Set[str]:
        interpretations = {
            1: {'sub', 'iss', 'aud', 'token_id'},
            2: {'email'},
            3: {'given_name', 'family_name', 'name'},
            4: {'idp', 'idp_name', 'eppn', 'eptid', 'affiliation', 'ou', 'oidc', 'cert_subject_dn'}
          }
        return interpretations[self.value]


class PTokens:
    """
    Encapsulates all the tokens to be included in the Cookie
    Assumes all the passed tokens are valid and decoded Identity claims are specified as well
    """
    def __init__(self, *, id_token: str, idp_claims: dict, access_token: str = None, refresh_token: str = None):
        """
        :param id_token identity token
        :param idp_claims identity claims
        :param access_token access token
        :param refresh_token refresh token
        """
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.id_token = id_token
        self.idp_claims = idp_claims


class VouchEncoder:
    """
    Responsible for decoding/encoding a Vouch Cookie
    """
    def __init__(self, *, secret: str, compression: bool = True):
        """
        :param secret vouch jwt secret
        :param compression flag indicating if compression is enabled/disabled
        """
        self.secret = secret
        self.compression = compression

    @staticmethod
    def _generate_custom_claims(*, idp_claims: dict,
                                custom_claims_to_include: List[CustomClaimsType]) -> Tuple[dict, str]:
        """
        Generate the custom claims based on the IDP Claims as per the configuration
        :param idp_claims IDP Claims
        :param custom_claims_to_include custom claims to be included in the cookie

        :return Custom Claims or None, username or None
        """
        result = {}
        username = None
        for claim_type in custom_claims_to_include:
            for claim in claim_type.interpret():
                value = idp_claims.get(claim, None)
                if value is not None:
                    result[claim] = value
                if claim == "email":
                    username = value
        return result, username

    def encode(self, *, custom_claims_type: List[CustomClaimsType], p_tokens: PTokens,
               validity_in_seconds: int) -> Tuple[ValidateCode, Union[Exception, str]]:
        """
        Encodes a vouch cookie
        :param custom_claims_type list of custom claims to be included in the cookie
        :param p_tokens Provider Tokens and claims
        :param validity_in_seconds validity in seconds for the cookie

        :return ValidateCode or None, exception or None, vouch cookie or None
        """
        if p_tokens.id_token is None or p_tokens.idp_claims is None:
            return ValidateCode.UNSPECIFIED_ID_TOKEN, None

        custom_claims, username = self._generate_custom_claims(idp_claims=p_tokens.idp_claims,
                                                               custom_claims_to_include=custom_claims_type)

        vouch_claims = {"username": username, "sites": [], "CustomClaims": custom_claims, "PIdToken": p_tokens.id_token}

        if p_tokens.access_token is not None:
            vouch_claims["PAccessToken"] = p_tokens.access_token

        if p_tokens.refresh_token is not None:
            vouch_claims["PRefreshToken"] = p_tokens.refresh_token

        return JWTManager.encode_and_compress(claims=vouch_claims, secret=self.secret,
                                              compression=self.compression,
                                              validity=validity_in_seconds)

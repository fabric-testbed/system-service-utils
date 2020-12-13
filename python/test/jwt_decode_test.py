import unittest
import jwt
import time

from fss_utils.jwt_validate import validate_jwt, fetch_pub_keys, ValidateCode


class JWTTester(unittest.TestCase):

    def setUp(self):
        self.url = "https://cilogon.org/oauth2/certs"
        self.testToken = {"email": "ibaldin@renci.org", "given_name": "Some", "family_name": "One",
                          "name": "Some One", "iss": "https://cilogon.org", "aud": "cilogon:foo",
                          "sub": "http://cilogon.org/serverT/users/241998",
                          "token_id": "https://cilogon.org/oauth2/idToken/1234567898",
                          "auth_time": "1607382404", "exp": 1607383305, "iat": 1607382405, "roles": [
                            "CO:members:all",
                            "CO:members:active",
                            "CO:admins",
                            "CO:COU:project-leads:members:active",
                            "CO:COU:project-leads:members:all",
                            "CO:COU:abf0014e-72f5-44ab-ac63-5ec5a5debbb8-pm:members:active",
                            "CO:COU:abf0014e-72f5-44ab-ac63-5ec5a5debbb8-pm:members:all"
                            ],
                          'exp': int(time.time()) + 1000}

    def testFetchKeys(self):
        """ test fetching keys from a real endpoint """
        vc, keys = fetch_pub_keys(self.url)
        assert vc is None and keys is not None

    def testEncodeDecode(self):
        """ test simple symmetric encoding/decoding """
        encoded_token = jwt.encode(self.testToken, key='secret', algorithm='HS256')
        jwt.decode(encoded_token, key='secret', algorithms=['HS256'], audience='cilogon:foo')

    @unittest.skip("Get a real token and a real audience")
    def testDecode(self):
        """ this test requires a real token and a real audience (which is CI Logon client ID)"""
        vc, e = validate_jwt(self.testToken2, self.url, self.audience)
        assert vc is ValidateCode.VALID and e is None
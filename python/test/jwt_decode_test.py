import unittest
import jwt
import time
import datetime

from fss_utils.jwt_validate import JWTValidator, ValidateCode


class JWTTester(unittest.TestCase):

    def setUp(self):
        self.url ="https://cilogon.org/oauth2/certs"
        # YOU NEED A REAL CI LOGON CLIENT ID
        self.audience = "cilogon:/client_id/123456789"
        self.period = datetime.timedelta(minutes=1)
        self.validator = JWTValidator(self.url, self.audience, self.period)
        self.testToken = {"email": "user@domain.net", "given_name": "Some", "family_name": "One",
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
        self.testToken2 = "you need a real token"

    def testFetchKeys(self):
        """ test fetching keys from a real endpoint """
        vc, e = self.validator.fetch_pub_keys()
        assert vc is None and e is None

    def testEncodeDecode(self):
        """ test simple symmetric encoding/decoding """
        encoded_token = jwt.encode(self.testToken, key='secret', algorithm='HS256')
        jwt.decode(encoded_token, key='secret', algorithms=['HS256'], audience='cilogon:foo')

    @unittest.skip("Get a real token and a real audience")
    def testDecode(self):
        """ this test requires a real token and a real audience (which is CI Logon client ID)"""
        vc, e = self.validator.validate_jwt(self.testToken2)
        print(vc)
        print(e)
        assert vc is ValidateCode.VALID and e is None
        print("Sleeping for 30 seconds")
        time.sleep(30)
        vc, e = self.validator.validate_jwt(self.testToken2)
        print(vc)
        print(e)
        assert vc is ValidateCode.VALID and e is None
        print("Sleeping for 40 seconds")
        time.sleep(40)
        vc, e = self.validator.validate_jwt(self.testToken2)
        print(vc)
        print(e)
        assert vc is ValidateCode.VALID and e is None
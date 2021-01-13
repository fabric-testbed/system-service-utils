import unittest
import jwt
import time
import datetime

from fss_utils.jwt_validate import JWTValidator
from fss_utils.jwt_manager import ValidateCode


class JWTTester(unittest.TestCase):

    def setUp(self):
        self.url = "https://cilogon.org/oauth2/certs"
        self.right_audience = "cilogon:/client_id/73bb503829ff96ad948f41b1d8e2a2a5"
        self.wrong_audience = "cilogon:/client_id/1234567890"
        self.period = datetime.timedelta(seconds=10)
        self.default_validator = JWTValidator(url=self.url, refresh_period=self.period)
        self.validator = None
        self.testToken = {"email": "user@domain.net", "given_name": "Some", "family_name": "One",
                          "name": "Some One", "iss": "https://cilogon.org", "aud": "cilogon:foo",
                          "sub": "https://cilogon.org/serverT/users/241998",
                          "token_id": "https://cilogon.org/oauth2/idToken/1234567898",
                          "auth_time": "1607382404", "iat": 1607382405, "roles": [
                            "CO:members:all",
                            "CO:members:active",
                            "CO:admins",
                            "CO:COU:project-leads:members:active",
                            "CO:COU:project-leads:members:all",
                            "CO:COU:abf0014e-72f5-44ab-ac63-5ec5a5debbb8-pm:members:active",
                            "CO:COU:abf0014e-72f5-44ab-ac63-5ec5a5debbb8-pm:members:all"
                            ],
                          'exp': int(time.time()) + 1000}
        self.testToken2 = "eyJ0eXAiOiJKV1QiLCJraWQiOiIyNDRCMjM1RjZCMjhFMzQxMDhEMTAxRUFDNzM2MkM0RSIsImFsZyI6IlJTMjU2I" \
                          "n0.eyJlbWFpbCI6ImliYWxkaW5AcmVuY2kub3JnIiwiZ2l2ZW5fbmFtZSI6IklseWEiLCJmYW1pbHlfbmFtZSI6Ik" \
                          "JhbGRpbiIsIm5hbWUiOiJJbHlhIEJhbGRpbiIsImlzcyI6Imh0dHBzOi8vY2lsb2dvbi5vcmciLCJzdWIiOiJodHR" \
                          "wOi8vY2lsb2dvbi5vcmcvc2VydmVyVC91c2Vycy8yNDE5OTgiLCJhdWQiOiJjaWxvZ29uOi9jbGllbnRfaWQvNzNi" \
                          "YjUwMzgyOWZmOTZhZDk0OGY0MWIxZDhlMmEyYTUiLCJ0b2tlbl9pZCI6Imh0dHBzOi8vY2lsb2dvbi5vcmcvb2F1d" \
                          "GgyL2lkVG9rZW4vMTk0ZGFiMDUzMzcxMGY0ZjM0YTEzNjYxNzQyMDQ1NTIvMTYwNzk3ODE1NDk5MyIsImF1dGhfdG" \
                          "ltZSI6IjE2MDc5NzgxNTMiLCJleHAiOjE2MDc5NzkwNTQsImlhdCI6MTYwNzk3ODE1NCwicm9sZXMiOlsiQ086bWV" \
                          "tYmVyczphbGwiLCJDTzptZW1iZXJzOmFjdGl2ZSIsIkNPOmFkbWlucyIsIkNPOkNPVTpwcm9qZWN0LWxlYWRzOm1l" \
                          "bWJlcnM6YWN0aXZlIiwiQ086Q09VOnByb2plY3QtbGVhZHM6bWVtYmVyczphbGwiLCJDTzpDT1U6YWJmMDAxNGUtN" \
                          "zJmNS00NGFiLWFjNjMtNWVjNWE1ZGViYmI4LXBtOm1lbWJlcnM6YWN0aXZlIiwiQ086Q09VOmFiZjAwMTRlLTcyZj" \
                          "UtNDRhYi1hYzYzLTVlYzVhNWRlYmJiOC1wbTptZW1iZXJzOmFsbCJdfQ.Uats19baYgA8mOllbPIDN_cpbXnPLPHu" \
                          "_QE5cBjlgu4KH7DSv0_15d-wjY59gJQUPq42Dg4cbgEzsfrNh_I7GldYCbopCWSv5S7rudJKbiz-gInPmDITGuOFH" \
                          "luOXYkEzJNJ1uxlUOvvQtyrvsCM2DuvSrd2FeBIY0MRHI92UEuvpjiCKn5JD-PhcFv8CUixityBXwewICvFo9k7YV" \
                          "70PvaL0SFzKskaofrdL8HialvWgWO26qEXsF2_CSUkgmTI_GikuVamUU3eP8jP7TntsqD_TBXKIKis2y8Kg9ao5N9" \
                          "OPu8sZ3Y9DTtqLeJKp7tsLsdGe6F_m58ozRck61_trA"

        self.testToken3 = "eyJ0eXAiOiJKV1QiLCJraWQiOiIyNDRCMjM1RjZCMjhFMzQxMDhEMTAxRUFDNzM2MkM0RSIsImFsZyI6IlJTMjU2I" \
                          "n0.eyJlbWFpbCI6ImliYWxkaW5AcmVuY2kub3JnIiwiZ2l2ZW5fbmFtZSI6IklseWEiLCJmYW1pbHlfbmFtZSI6Ik" \
                          "JhbGRpbiIsIm5hbWUiOiJJbHlhIEJhbGRpbiIsImlzcyI6Imh0dHBzOi8vY2lsb2dvbi5vcmciLCJzdWIiOiJodHR" \
                          "wOi8vY2lsb2dvbi5vcmcvc2VydmVyVC91c2Vycy8yNDE5OTgiLCJhdWQiOiJjaWxvZ29uOi9jbGllbnRfaWQvNzNi" \
                          "YjUwMzgyOWZmOTZhZDk0OGY0MWIxZDhlMmEyYTUiLCJ0b2tlbl9pZCI6Imh0dHBzOi8vY2lsb2dvbi5vcmcvb2F1d" \
                          "GgyL2lkVG9rZW4vMTk0ZGFiMDUzMzcxMGY0ZjM0YTEzNjYxNzQyMDQ1NTIvMTYwNzk3ODE1NDk5MyIsImF1dGhfdG" \
                          "ltZSI6IjE2MDc5NzgxNTMiLCJleHAiOjE2MDc5NzkwNTQsImlhdCI6MTYwNzk3ODE1NCwicm9sZXMiOlsiQ086bWV" \
                          "tYmVyczphbGwiLCJDTzptZW1iZXJzOmFjkNPOmFkbWlucyIsIkNPOkNPVTpwcm9qZWN0LWxlYWRzOm1l" \
                          "bWJlcnM6YWN0aXZlIiwiQ086Q09VOnByb2plY3QtbGVhZHM6bWVtYmVyczphbGwiLCJDTzpDT1U6YWJmMDAxNGUtN" \
                          "zJmNS00NGFiLWFjNjMtNWVjNWE1ZGViYmI4LXBtOm1lbWJlcnM6YWN0aXZlIiwiQ086Q09VOmFiZjAwMTRlLTcyZj" \
                          "UtNDRhYi1hYzYzLTVlYzVhNWRlYmJiOC1wbTptZW1iZXJzOmFsbCJdfQ.Uats19baYgA8mOllbPIDN_cpbXnPLPHu" \
                          "_QE5cBjlgu4KH7DSv0_15d-wjY59gJQUPq42Dg4cbgEzsfrNh_I7GldYCbopCWSv5S7rudJKbiz-gInPmDITGuOFH" \
                          "luOXYkEzJNJ1uxlUOvvQtyrvsCM2DuvSrd2FeBIY0MRHI92UEuvpjiCKn5JD-PhcFv8CUixityBXwewICvFo9k7YV" \
                          "70PvaL0SFzKskaofrdL8HialvWgWO26qEXsF2_CSUkgmTI_GikuVamUU3eP8jP7TntsqD_TBXKIKis2y8Kg9ao5N9" \
                          "OPu8sZ3Y9DTtqLeJKp7tsLsdGe6F_m58ozRck61_trA"

    def testFetchKeys(self):
        """ test fetching keys from a real endpoint (succeed) """
        self.validator = JWTValidator(url=self.url, refresh_period=self.period)
        vc, e = self.validator.fetch_pub_keys()
        assert vc is None and e is None

    def testEncodeDecode(self):
        """ test simple symmetric encoding/decoding (succeed) """
        encoded_token = jwt.encode(self.testToken, key='secret', algorithm='HS256')
        jwt.decode(encoded_token, key='secret', algorithms=['HS256'],
                   options={"verify_exp": True, "verify_aud": True},
                   audience='cilogon:foo')

    def testNoExpiredNoAudience(self):
        """ validate signature, ignore expiration and audience (succeed) """
        # audience is set to None in this case
        vc, e = self.default_validator.validate_jwt(token=self.testToken2)
        assert vc is ValidateCode.VALID

    def testNoExpiredRightAudience(self):
        """ validate signature, ignore expiration, check audience (succeed) """
        self.validator = JWTValidator(url=self.url, refresh_period=self.period,
                                      audience=self.right_audience)
        vc, e = self.validator.validate_jwt(token=self.testToken2)
        assert vc is ValidateCode.VALID

    def testNoExpiredWrongAudience(self):
        """ validate signature, ignore expiration, check audience (fail) """
        self.validator = JWTValidator(url=self.url, refresh_period=self.period,
                                      audience=self.wrong_audience)
        vc, e = self.validator.validate_jwt(token=self.testToken2)
        assert vc is ValidateCode.INVALID and str(e) == "Invalid audience"

    def testStrictExpired(self):
        """ test for expiration (fail) """
        # audience is set to None in this case
        vc, e = self.default_validator.validate_jwt(token=self.testToken2, verify_exp=True)
        assert vc is ValidateCode.INVALID and str(e) == "Signature has expired"

    def testBadToken(self):
        """ test an unparsable token (fail) """
        vc, e = self.default_validator.validate_jwt(token=self.testToken3)
        assert vc is ValidateCode.UNPARSABLE_TOKEN

    def testKeyRefetch(self):
        """ test key refetch from JWK endpoint """
        vc, e = self.default_validator.validate_jwt(token=self.testToken2)
        assert vc is ValidateCode.VALID
        print("Sleeping for 5 seconds")
        time.sleep(5)
        vc, e = self.default_validator.validate_jwt(token=self.testToken2)
        assert vc is ValidateCode.VALID
        print("Sleeping for 6 seconds")
        time.sleep(6)
        vc, e = self.default_validator.validate_jwt(token=self.testToken2)
        assert vc is ValidateCode.VALID

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
import time

from fss_utils.jwt_manager import ValidateCode, JWTManager
from fss_utils.vouch_encoder import VouchEncoder, CustomClaimsType, PTokens


class VouchEncoderTest(unittest.TestCase):
    def setUp(self):
        self.valid_token = "eyJ0eXAiOiJKV1QiLCJraWQiOiIyNDRCMjM1RjZCMjhFMzQxMDhEMTAxRUFDNzM2MkM0RSIsImFsZyI6IlJTMjU2I" \
                           "n0.eyJlbWFpbCI6Imt0aGFyZTEwQGVtYWlsLnVuYy5lZHUiLCJnaXZlbl9uYW1lIjoiS29tYWwiLCJmYW1pbHlfbm" \
                           "FtZSI6IlRoYXJlamEiLCJuYW1lIjoiS29tYWwgVGhhcmVqYSIsImlzcyI6Imh0dHBzOi8vY2lsb2dvbi5vcmciLCJ" \
                           "zdWIiOiJodHRwOi8vY2lsb2dvbi5vcmcvc2VydmVyQS91c2Vycy8xMTkwNDEwMSIsImF1ZCI6ImNpbG9nb246L2Ns" \
                           "aWVudF9pZC83M2JiNTAzODI5ZmY5NmFkOTQ4ZjQxYjFkOGUyYTJhNSIsInRva2VuX2lkIjoiaHR0cHM6Ly9jaWxvZ" \
                           "29uLm9yZy9vYXV0aDIvaWRUb2tlbi82ZGVjZDNmNDI2ODZmMDJiZDUzNTY0MDRlYTZmNTc4MS8xNjEwNDAwODE5NT" \
                           "U5IiwiYXV0aF90aW1lIjoiMTYxMDQwMDYzMyIsImV4cCI6MTYxMDQwMTcxOSwiaWF0IjoxNjEwNDAwODE5fQ.P6do" \
                           "VgTGDzPOVTIkUZH89FFaaVlC9zKg-94nDE5evGWxtgG_3jHViajXFEsDYlDN7SEZoX9IPN0cx2ddERl5HyBeMYpkS" \
                           "xDFxHCDMuiN1Boj9RpH45dZYzmJvCYGRdP_eOr2R7cHpZLWrS2K6DrHmHBlPoLQjRUUR1Y-ppMRm7M2FIl7pRARHj" \
                           "gA_cxoeMTovlNwoeSSNpYXYygPx0Z7YxSZI35NpWlpxUlfume9DE29yJ9zpjsndZ1H3eUQRxsQvXI0n3O8vvL91Gs" \
                           "xuBSlnR3Tt_jpdxtR2MaJnV7OVKQK9LUVhuNWoVP3e6RIIxzolLIFEI0BT-SkR5nVGYEgfQ"

        self.expired_cookie = "H4sIAAAAAAAA_4xVWZOjOBL-RxMIitrh0S4DhrZEI3QgvQFyN4eEVeUD0K_fcFXPzF4TsW-glL4rMyLPW963aT" \
                              "cUQ55RlwE0ZNdsxmH3lr1mk63ZWx79dt5y0Plsa01yk1X2mpmb16TJJkm8lCm7Ca6vp5ndxRZqeaTD6S13TY11" \
                              "t2WvHHjXbEKgC_CjpegquL49z5_EipdP4rHh60P60b0YorFNtW5n_KPh5QMa4SGCdZFCAF0yCLJz8jAF0GEjiH" \
                              "hBPnTQxGtRZdfMfOnIxsvQBPgi6lxDst9JDvqGL3fFw_Fk2KQ-78q-5fp6ZtFdcKCfb1ja951h7-Kzrqwy7F77" \
                              "Yd9y-tR4an3Qt2_PmnZP_ZnpPXXcu2L4_SF8fW199WiH8NGZ7un_T9zKj26CLz__DX9GQAx_YOxeT1v0ZwYnE2" \
                              "1yi5ysc1_W-f4UsOe3O7l4LcjOg2S3ZsMyqDT6kDx85vTUd1FHvHTu8jj5yLZpNLf-y70N8vnkR72q8QUOkZUJ" \
                              "fjQ-u5-c8OSB9YLnBrppQQRuaBShTMsV8ThEZAeEwVoYup5c7EOy84pD6UMnAjTGw49qGWicjMJnrgNfmJ-5H7" \
                              "HXHeH_8vMQNfOaQ_YQHI2yRo596n95QDL5grARHfZGOLGgA3TFgQJJVC-4WOUY--Kp0RcPSMQKD-ULOgiH3G6B" \
                              "zyz1vpJcbrJGl1-Y_28e23-8eyCS6-LwcxNuF0rOJuSXniT5JA8_X-TIBngQmyQUoMPu77Tkf2T8zEPW-htMmS" \
                              "i5_t5Qe2Jjghu6Hqo57xlILPF1fqZhTCeEmslbqbFN6YH3JpborJMXQvEFU0DLuq8YlTGZLYIT-CBkX1FPu4qD" \
                              "tAM2rIjM29hSwi2Dk77Dt1Cfqb0KrdIuzQ-f9bpcBFXpmVmKa4UxkB5n6tp5653NTJ4Ju_KpZ5_6TNjzxF6FWU" \
                              "LFdA35mjcmstRloUp0rXwNS8_eOOvWLs2zNpVDS6XHNcrRpK_URJLH9io4SL78Mslccq24fTQMbkWNJQvUzCZ1" \
                              "aVJ0Y3Mif_m5ng368sN_LjLu385TZIujlNCsToz5pExuUS3HliNLYvTtbHBdfeX7kHFfKe9v7_vC5fzM8Y3NGl" \
                              "M3rV__KCyOPWLpLSATTpQHSFWjvKVi5dOnnxuZ9wN2-i7GzEPTspEZ9QxIIGMRdok9FEfdNDpeyaQYSvQrqy1i" \
                              "nr0QiovGi6gIbIGBvRBjZwj0K6m1ZDEFFddBw_GxqPOGOWYEU7ihka1MNFVJHojAPtQn31_8imeuMiGEo77IpK" \
                              "9aD9ii3jdY574gOVd0feVk3-BEXjhT31oKXptAFSwGITFWImaPtO4L5lFANN5Dpm_UrLJl7IUcbQInQEuy_46T" \
                              "eCO1ldAL3zH_7PcXH_jp6LwfGGBf8xuH77hWBU67hZjnfGqrfN3wtA-e_f6X-ko0RnB6zsNe8uQ5___F1xRVmB" \
                              "X1bq3GfdIcsahYtKqDbiCLbrwuA8JR39XsXQK7nGr8nR_Rh5xR3zhtaMLiE9n7jcvC1ltcBfTY-HlCKI4bBr12" \
                              "UrqL1VS6cmljFohZvaixTzhTRrDecBP2zGUer_VNjfTWppK1gf6GeZKRCRA29wHTSUgACoVGCFMM-YguImCrmP" \
                              "GENrAv6ARaf_1QQd403MLaRxvyl0AEKOUHfEK-5IhhiNK1oJPiqBZhOU7beVS6O6BYxuytSNmdeRYoP1pJjJxK" \
                              "mEAJejsnCqEax2cyuS4tF-ThjyphRUnDDU2RpboMKpqT9rjXPNEMJrmhji6N6Quk5aED6oMae6qC_ACnnlETlR" \
                              "3B7Jxegparhzz0QUH2HxW_oQ7YV2nslXpqKniY8rpPWRxeaSAWZNiVUTmwVL8iQ18qfqOMgulU6xvTSHdJv3Tp" \
                              "5x7U5-NuKMZfO4RMC3TdXztUy4fi6JLN3m9bM7kd_z6kBfz9vkvucxvu0x_BbU3TAIe4Wd0_spNBb6VP_xkAAP" \
                              "__xxoL6rQIAAA="

        self.secret = "kmDDgMLGThapDV1QnhWPJd0oARzjLa5Zy3bQ8WfOIYk="

    def test_encode_decode_vouch_cookie(self):
        # Decode CI Logon Identity Token to get IDP Claims
        code, id_token = JWTManager.decode(cookie=self.valid_token, verify=False, compression=False)
        self.assertEqual(code, ValidateCode.VALID)
        self.assertTrue(isinstance(id_token, dict))

        p_tokens = PTokens(id_token=self.valid_token, idp_claims=id_token)

        encoder = VouchEncoder(secret="super-secret")

        # Create Vouch Cookie with validity 5 seconds
        code, cookie = encoder.encode(custom_claims_type=[CustomClaimsType.PROFILE, CustomClaimsType.EMAIL,
                                                          CustomClaimsType.OPENID],
                                      p_tokens=p_tokens, validity_in_seconds=5)

        self.assertEqual(code, ValidateCode.VALID)
        self.assertTrue(isinstance(cookie, str))

        # Decode the vouch cookie
        code, decoded_cookie = JWTManager.decode(cookie=cookie, compression=True, secret="super-secret")

        # Cookie decode successfully
        self.assertEqual(code, ValidateCode.VALID)
        self.assertTrue(isinstance(decoded_cookie, dict))

        # Sleep for 10 seconds, cookie has expired and the decode should fail now
        time.sleep(10)

        # Decoding Vouch cookie fails after 10 seconds
        code, decoded_cookie = JWTManager.decode(cookie=cookie, compression=True, secret="super-secret")
        self.assertEqual(code, ValidateCode.INVALID)

    def test_encode_vouch_cookie_missing_id_token(self):
        # Decode CI Logon Identity Token to get IDP Claims
        code, id_token = JWTManager.decode(cookie=self.valid_token, verify=False, compression=False)
        self.assertEqual(code, ValidateCode.VALID)
        self.assertTrue(isinstance(id_token, dict))

        p_tokens = PTokens(id_token=None, idp_claims=id_token)

        encoder = VouchEncoder(secret="super-secret")

        # Create Vouch Cookie with validity 5 seconds
        code, cookie = encoder.encode(custom_claims_type=[CustomClaimsType.PROFILE, CustomClaimsType.EMAIL,
                                                          CustomClaimsType.OPENID],
                                      p_tokens=p_tokens, validity_in_seconds=5)

        self.assertEqual(code, ValidateCode.UNSPECIFIED_ID_TOKEN)
        self.assertIsNone(cookie)

    def test_encode_vouch_cookie_missing_id_claims(self):
        # Decode CI Logon Identity Token to get IDP Claims
        code, id_token = JWTManager.decode(cookie=self.valid_token, verify=False, compression=False)
        self.assertEqual(code, ValidateCode.VALID)
        self.assertTrue(isinstance(id_token, dict))

        p_tokens = PTokens(id_token=self.valid_token, idp_claims=None)

        encoder = VouchEncoder(secret="super-secret")

        # Create Vouch Cookie with validity 5 seconds
        code, cookie = encoder.encode(custom_claims_type=[CustomClaimsType.PROFILE, CustomClaimsType.EMAIL,
                                                          CustomClaimsType.OPENID],
                                      p_tokens=p_tokens, validity_in_seconds=5)

        self.assertEqual(code, ValidateCode.UNSPECIFIED_ID_TOKEN)
        self.assertIsNone(cookie)

    def test_decode_expired_cookie(self):
        # decode cookie generated by Vouch without verifying
        code, decoded_cookie = JWTManager.decode(cookie=self.expired_cookie, compression=True, secret=self.secret,
                                                 verify=False)
        self.assertEqual(code, ValidateCode.VALID)

        # decode cookie generated by Vouch with verification
        code, decoded_cookie = JWTManager.decode(cookie=self.expired_cookie, compression=True, secret=self.secret)
        self.assertEqual(code, ValidateCode.INVALID)
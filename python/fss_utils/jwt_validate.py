import requests
import jwt
import json
import enum
import datetime

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

    def interpret(self, exception=None):
        interpretations = {
            1: "Token is valid",
            2: "Token does not specify key ID",
            3: "Token does not specify algorithm",
            4: "Unable to find public key at JWK endpoint",
            5: "Token signature is invalid",
            6: "Unable to fetch keys from the endpoint",
            7: "Unable to parse token",
            8: "Unable to decode public keys"
          }
        if exception is None:
            return interpretations[self.value]
        else:
            return str(exception) + ". " + interpretations[self.value]


class JWTValidator:
    """This class caches keys retrieved from a specified endpoint
    and uses them to validate provided JWTs"""

    def __init__(self, url, refreshPeriod, audience=None):
        """ Initialize a validator with an endpoint URL presenting JWKs,
        a refresh period for keys expressed as datetime.timedelta and
        audience (i.e. CI Logon client id cilogon:/client_id/1234567890).
        :param url:
        :param refreshPeriod:
        :param audience:
        """
        self.url = url
        self.aud = audience
        assert refreshPeriod is None or isinstance(refreshPeriod, datetime.timedelta)
        self.cachePeriod = refreshPeriod
        self.pubKeys = None
        self.keysFetched = None

    def fetch_pub_keys(self):
        """
        Fetch JWKs from an endpoint, return a dictionary of key ids vs public key values (RSA)
        Returns a tuple ValidateCode, public key dict. Code is None in case of success,
        dict is none in case of failure.
        :return ValidateCode or None, exception or None:
        """
        if self.keysFetched is not None:
            if datetime.datetime.now() < self.keysFetched + self.cachePeriod:
                return None, None

        r = requests.get(self.url)
        if r.status_code != 200:
            return ValidateCode.UNABLE_TO_FETCH_KEYS, None

        self.keysFetched = datetime.datetime.now()

        try:
            self.pubKeys = dict()
            jwks = json.loads(r.text)
            for jwk in jwks['keys']:
                kid = jwk['kid']
                self.pubKeys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
            return None, None
        except Exception as e:
            return ValidateCode.UNABLE_TO_DECODE_KEYS, e

    def validate_jwt(self, token, verify_exp=False):
        """
        Validate a token using a JWKs object retrieved from an endpoint.
        Returns a tuple ValidateCode code, exception object if it occurred (or None).
        Requires the token, the endpoint URL and the audience, i.e. CI Logon client ID
        cilogon:/client_id/1234567890
        You can turn on expiration validation (off by default), but beware most tokens
        live just a few minutes.
        :param token:
        :param verify_exp:
        :return tuple ValdateCode, Exception:
        """
        r, e = self.fetch_pub_keys()
        if r is not None:
            return r, e

        # get kid from token
        try:
            kid = jwt.get_unverified_header(token).get('kid', None)
            alg = jwt.get_unverified_header(token).get('alg', None)
        except jwt.DecodeError as e:
            return ValidateCode.UNPARSABLE_TOKEN, e

        if kid is None:
            return ValidateCode.UNSPECIFIED_KEY, None

        if alg is None:
            return ValidateCode.UNSPECIFIED_ALG, None

        if kid not in self.pubKeys.keys():
            return ValidateCode.UNKNOWN_KEY, None

        key = self.pubKeys[kid]

        options = dict()
        if verify_exp:
            options["verify_exp"] = True
        else:
            options["verify_exp"] = False

        if self.aud is None:
            options["verify_aud"] = False
        else:
            options["verify_aud"] = True

        # options https://pyjwt.readthedocs.io/en/latest/api.html
        try:
            jwt.decode(token, key=key, algorithms=[alg], options=options, audience=self.aud)
        except Exception as e:
            return ValidateCode.INVALID, e

        return ValidateCode.VALID, None

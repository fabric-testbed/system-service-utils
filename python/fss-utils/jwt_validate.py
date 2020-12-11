import requests
import jwt
import json
import enum

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
            4: "Unable to find public key at endpoint",
            5: "Token signature is invalid",
            6: "Unable to fetch keys from the endpoint",
            7: "Unable to parse token",
            8: "Unable to decode public keys"
          }
        if exception is None:
            return interpretations[self.value]
        else:
            return str(exception) + ". " + interpretations[self.value]


def fetch_pub_keys(url):
    """
    Fetch JWKs from an endpoint, return a dictionary of key ids vs public key values (RSA)
    Returns a tuple ValidateCode, public key dict. Code is None in case of success,
    dict is none in case of failure.
    :return ValidateCode or None, None or dict of keys:
    """
    r = requests.get(url)
    if r.status_code != 200:
        return ValidateCode.UNABLE_TO_FETCH_KEYS, None

    try:
        pub_keys = dict()
        jwks = json.loads(r.text)
        for jwk in jwks['keys']:
            kid = jwk['kid']
            pub_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        return None, pub_keys
    except Exception:
        return ValidateCode.UNABLE_TO_DECODE_KEYS, None


def validate_jwt(token, endpoint):
    """
    Validate a token using a JWKs object retrieved from an endpoint.
    Returns a ValidateCode code and exception object if it occurred.
    :return tuple ValdateCode, Exception:
    """
    code, pub_keys = fetch_pub_keys(endpoint)
    if pub_keys is None:
        return code, None

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

    if kid not in pub_keys.keys():
        return ValidateCode.UNKNOWN_KEY, None

    key = pub_keys[kid]

    try:
        jwt.decode(token, key=key, algorithms=[alg])
    except Exception as e:
        return ValidateCode.INVALID, e

    return ValidateCode.VALID, None



[![PyPI](https://img.shields.io/pypi/v/fabric-fss-utils?style=plastic)](https://pypi.org/project/fabric-fss-utils/)

# Overview

Python library for supporting FABRIC System Services. Includes multiple modules:

- [jwt_validate](fss_utils/jwt_validate.py) - validates JWT against a JWKS endpoint

See [test](test/) folder for examples of use

# Installation

For developing and testing the FIM code itself use editable install (from top-level directory)
from python/ folder
```bash
(infomodel) $ pip install -e .
```

As a dependency use PyPi
```bash
$ pip install fabric-fss-utils
$  python
>>> from fss_utils.jwt_validate import JWTValidator, ValidateCode
>>> token = "..."
>>> validator = JWTValidator(cert_end_point, audience, datetime.timedelta(minutes=5))
>>> validator.validate_jwt(token)
```

# Testing

Use `pytest`:
```bash
$ pytest test/
```
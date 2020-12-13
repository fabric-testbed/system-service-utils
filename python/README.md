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
$ pip install fss-utils
```
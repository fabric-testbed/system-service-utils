import unittest

from http import HTTPStatus
from fss_utils.http_errors import HTTPErrorTuple


class HTTPErrorTupleTest(unittest.TestCase):

    def testTuple(self):
        a, b, c = HTTPErrorTuple(HTTPStatus.INTERNAL_SERVER_ERROR, "serious error").astuple()
        assert(a == "Internal Server Error")
        assert(b == 500)
        assert(c == { "X-Error": "serious error"})

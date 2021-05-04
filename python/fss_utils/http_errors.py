#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2021 FABRIC Testbed
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
# Author Ilya Baldin (ibaldin@renci.org)

from http import HTTPStatus


class HTTPErrorTuple:
    """
    Small helper class to return HTTP error in the format UIS, PR like.
    Use it as follows:
    return HTTPErrorTuple(HTTPStatus.INTERNAL_SERVER_ERROR, "Horrible internal error details").astuple()
    You will get a tuple
    ("Internal Server Error", 500, { "X-Error": "Horrible internal error details"})
    """

    def __init__(self, status, xerror: str):
        self.code = status.real
        self.phrase = status.phrase
        self.xerror = xerror

    def astuple(self):
        return self.phrase, self.code, {"X-Error": self.xerror}


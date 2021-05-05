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
from flask import Response, request


class HTTPErrorTuple:
    """
    Small helper class to return HTTP error in the format UIS, PR like.
    Use it as follows:
    return HTTPErrorTuple(status=HTTPStatus.INTERNAL_SERVER_ERROR,
                          body="Non standard error return",
                          xerror="Horrible internal error details").astuple()
    You will get a flask.Response
    ("Non standard error return", 500, { "X-Error": "Horrible internal error details"})
    If you don't want CORS headers included, add cors=False as a parameter to constructor.
    """

    def __init__(self, *, request, status, body: str = None, xerror: str = None, cors: bool = True):
        self.request = request
        self.cors = cors
        self.body = body if body is not None else status.phrase
        self.code = status.real
        self.xerror = xerror

    def response(self) -> Response:
        r = Response()
        r.status_code = self.code
        r.data = self.body
        if self.cors:
            r.headers['Access-Control-Allow-Origin'] = self.request.headers.get('Origin', '*')
            r.headers['Access-Control-Allow-Credentials'] = 'true'
            r.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            r.headers['Access-Control-Allow-Headers'] = 'DNT, User-Agent, X-Requested-With, ' \
                                                        'If-Modified-Since, Cache-Control, ' \
                                                        'Content-Type, Range'
            r.headers['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range, X-Error'

        if self.xerror:
            r.headers['X-Error'] = self.xerror

        return r


def cors_response(status, body: str = None, xerror: str = None, cors: bool = True) -> Response:
    """
    Shortcut method to provide a cors response
    :param status:
    :param body:
    :param xerror:
    :param cors:
    :return:
    """
    r = HTTPErrorTuple(request=request, status=status, body=body, xerror=xerror, cors=cors)
    return r.response()

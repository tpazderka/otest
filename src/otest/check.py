"""
    Assertion test module
    ~~~~~~~~~~~~~~~~~~~~~

    :copyright: (c) 2016 by Roland Hedberg.
    :license: APACHE 2.0, see LICENSE for more details.
"""
from future.backports.urllib.parse import parse_qs

import json
import inspect
import traceback
import sys

from otest.events import EV_PROTOCOL_REQUEST
from otest.events import EV_PROTOCOL_RESPONSE
from otest.events import EV_REDIRECT_URL
from otest.events import EV_RESPONSE
from otest.events import EV_HTTP_RESPONSE

from oic.oic import message

__author__ = 'rolandh'

INFORMATION = 0
OK = 1
WARNING = 2
ERROR = 3
CRITICAL = 4
INTERACTION = 5
INCOMPLETE = 6
NOT_APPLICABLE = 7

STATUSCODE = ["INFORMATION", "OK", "WARNING", "ERROR", "CRITICAL",
              "INTERACTION", 'PARTIAL RESULT']

STATUSCODE_TRANSL = dict([(STATUSCODE[i], i) for i in range(len(STATUSCODE))])

END_TAG = "==== END ===="


class TestResult(object):
    name = 'test_result'

    def __init__(self, test_id, status=OK, name='', mti=False, message='',
                 **kwargs):
        self.test_id = test_id
        self.status = status
        self.name = name
        self.mti = mti
        self.message = message
        self.http_status = 0
        self.cid = ''
        self.extra = kwargs

    def __str__(self):
        if self.status:
            return '{}: status={}, message={}'.format(self.test_id,
                                                      STATUSCODE[self.status],
                                                      self.message)
        else:
            return '{}: status=?'.format(self.test_id)


class State(object):
    name = 'state'

    def __init__(self, test_id, status, name='', mti=False, message='',
                 context='', **kwargs):
        self.test_id = test_id
        self.status = status
        self.name = name
        self.mti = mti
        self.message = message
        self.context = context
        self.kwargs = kwargs

    def __str__(self):
        _info = {
            'ctx': self.context, 'id': self.test_id,
            'stat': STATUSCODE[self.status], 'msg': self.message
        }
        if self.status != OK:
            if self.context:
                txt = '{ctx}:{id}: status={stat}, message={msg}'.format(
                    **_info)
            else:
                txt = '{id}: status={stat}, message={msg}'.format(**_info)
        else:
            if self.context:
                txt = '{ctx}:{id}: status={stat}'.format(**_info)
            else:
                txt = '{id}: status={stat}'.format(**_info)

        if self.name:
            txt = '{} [{}]'.format(txt, self.name)

        return txt


class Check(object):
    """ General test
    """

    cid = "check"
    msg = "OK"
    mti = True
    state_cls = State

    def __init__(self, **kwargs):
        self._status = OK
        self._message = ""
        self.content = None
        self.url = ""
        self._kwargs = kwargs

    def _func(self, conv):
        return TestResult('')

    def __call__(self, conv=None, output=None):
        _stat = self._func(conv)
        if isinstance(_stat, dict):
            _stat = self.response(**_stat)

        if output is not None:
            output.append(_stat)
        return _stat

    def response(self, **kwargs):
        try:
            name = " ".join(
                [str(s).strip() for s in self.__doc__.strip().split("\n")])
        except AttributeError:
            name = ""

        res = self.state_cls(test_id=self.cid, status=self._status, name=name,
                             mti=self.mti)

        if self._message:
            res.message = self._message
        else:
            if self._status != OK:
                res.message = self.msg

        for key, val in kwargs.items():
            setattr(self, key, val)

        return res


class ExpectedError(Check):
    pass


class CriticalError(Check):
    status = CRITICAL


class Information(Check):
    status = INFORMATION


class Warnings(Check):
    status = WARNING


class Error(Check):
    status = ERROR


class ResponseInfo(Information):
    """Response information"""

    def _func(self, conv=None):
        self._status = self.status
        _msg = conv.events.last_item(EV_RESPONSE)

        if isinstance(_msg, str):
            self._message = _msg
        else:
            self._message = _msg.to_dict()

        return {}


class WrapException(CriticalError):
    """
    A runtime exception
    """
    cid = "exception"
    msg = "Test tool exception"

    def _func(self, conv=None):
        self._status = self.status
        self._message = traceback.format_exception(*sys.exc_info())
        return {}


class Other(CriticalError):
    """ Other error """
    msg = "Other error"


class CheckHTTPResponse(CriticalError):
    """
    Checks that the HTTP response status is within a specified range
    """
    cid = "http_response"
    msg = "Incorrect HTTP status_code"

    def _func(self, conv):
        _response = conv.events.last_item(EV_HTTP_RESPONSE)

        res = {}
        if not _response:
            return res

        if 'status_code' in self._kwargs:
            if _response.status_code not in self._kwargs['status_code']:
                self._status = self.status
                self._message = self.msg
                res["http_status"] = _response.status_code
        else:
            if _response.status_code >= 400:
                self._status = self.status
                self._message = self.msg
                res["http_status"] = _response.status_code

        return res


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    return None


def get_provider_info(conv):
    _pi = conv.entity.provider_info
    if not _pi:
        _pi = conv.provider_info
    return _pi


def get_protocol_response(conv, cls):
    return conv.events.get_messages(EV_PROTOCOL_RESPONSE, cls)


def get_protocol_request(conv, cls):
    return conv.events.get_messages(EV_PROTOCOL_REQUEST, cls)


def get_id_tokens(conv):
    res = []
    # In access token responses
    for inst in get_protocol_response(conv, message.AccessTokenResponse):
        try:
            res.append(inst["id_token"])
        except KeyError:
            pass

    # implicit, id_token in authorization response
    for inst in get_protocol_response(conv, message.AuthorizationResponse):
        try:
            res.append(inst["id_token"])
        except KeyError:
            pass

    return res


def get_signed_id_tokens(conv):
    res = []
    for item in conv.events.get_data(EV_RESPONSE):
        if isinstance(item, dict):
            ent = item
        else:
            try:
                ent = json.loads(item)
            except Exception as err:
                try:
                    ent = parse_qs(item)
                except:
                    continue
                else:
                    try:
                        res.append(ent['id_token'][0])
                    except KeyError:
                        pass
                    else:
                        continue
        try:
            res.append(ent['id_token'])
        except KeyError:
            pass

    return res


def get_authorization_request(conv, cls):
    authz_req = conv.events.get_data(EV_REDIRECT_URL)[0].split('?')[1]
    return cls().from_urlencoded(authz_req)

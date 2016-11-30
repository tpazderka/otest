import copy
import inspect
import logging
import sys

from future.backports.http.cookies import CookieError
from future.backports.http.cookies import SimpleCookie
from future.backports.urllib.parse import urlparse
from oic import oic
from oic.extension.oidc_fed import ProviderConfigurationResponse
from oic.oauth2 import ErrorResponse
from oic.utils.http_util import SeeOther

from otest import operation
from otest import OperationError

from otest.events import EV_HTTP_RESPONSE
from otest.events import EV_RESPONSE
from otest.events import OUTGOING
from otest.events import NoSuchEvent
from otest.events import EV_RUN
from otest.events import EV_PROTOCOL_RESPONSE
from otest.events import EV_REDIRECT_URL
from otest.events import EV_REQUEST
from otest.rp.response import Response
from otest.verify import Verify

from oic.oauth2.util import set_cookie

from oic.oic import message

__author__ = 'roland'

logger = logging.getLogger(__name__)


def save_response(events, resp, resp_cls, err_resp_cls):
    if 'error' in resp.message:
        _msgtype = err_resp_cls
    else:
        _msgtype = resp_cls

    if isinstance(resp, SeeOther):
        p = urlparse(resp.message)
        if p.query:
            _msg = _msgtype().from_urlencoded(p.query)
        elif p.fragment:
            _msg = _msgtype().from_urlencoded(p.query)
        else:
            _msg = ''
    else:
        _msg = copy.copy(resp.message)
        try:
            _msg = _msgtype().from_json(_msg)
        except Exception as err:
            _msg = _msgtype().from_urlencoded(_msg)

    events.store(EV_PROTOCOL_RESPONSE, _msg, direction=OUTGOING)
    events.store(EV_RESPONSE, resp.message, direction=OUTGOING)


class Operation(operation.Operation):
    def __call__(self, *args, **kwargs):
        if self.skip:
            return
        else:
            cls_name = self.__class__.__name__
            if self.tests["pre"]:
                _ver = Verify(self.check_factory, self.conv, cls_name=cls_name)
                _ver.test_sequence(self.tests["pre"])

            self.conv.events.store(EV_RUN, cls_name)
            res = self.run(*args, **kwargs)

            if res:
                return res


class Init(Operation):
    start_page = ''
    endpoint = ''

    def run(self, **kwargs):
        self.conv.events.store('start_page', self.start_page)
        if self.internal:
            res = self.conv.entity.server.http_request(self.start_page)
        else:
            res = SeeOther(self.start_page)
            return res
        self.conv.events.store(EV_HTTP_RESPONSE, res)
        if res.status_code in [302, 303]:
            loc = res.headers['location']
            try:
                self.conv.events.store('Cookie', res.headers['set-cookie'])
            except KeyError:
                pass
            logger.info('Redirect to {}'.format(loc))
            logger.debug('msg: {}'.format(res.text))
            self.conv.events.store(EV_REDIRECT_URL, loc, sub='init')
        elif res.status_code >= 400:
            logger.info('Error {}'.format(res.text))
            raise OperationError('Error response on HTTP request')
        return res

    def handle_response(self, resp, *args):
        self.conv.events.store(EV_PROTOCOL_RESPONSE,
                               message.AuthorizationResponse(**resp))


class ConfigurationResponse(Response):
    endpoint = 'providerinfo_endpoint'

    def __init__(self, conv, inut, sh, **kwargs):
        Response.__init__(self, conv, inut, sh, **kwargs)
        try:
            self.op_type = kwargs['op_type']
        except KeyError:
            self.op_type = ''
        else:
            del kwargs['op_type']
        self.msg_args = kwargs

    def handle_request(self, *args):
        return None

    def construct_message(self):
        op = self.conv.entity
        resp = op.providerinfo_endpoint()
        if resp.status == '200 OK' or resp.status == '201 Created':
            save_response(self.conv.events, resp, ProviderConfigurationResponse,
                          ErrorResponse)
        return resp


class RegistrationResponse(Response):
    endpoint = 'registration'

    def __init__(self, conv, inut, sh, **kwargs):
        Response.__init__(self, conv, inut, sh, **kwargs)
        try:
            self.op_type = kwargs['op_type']
        except KeyError:
            self.op_type = ''
        else:
            del kwargs['op_type']
        self.msg_args = kwargs

    def construct_message(self):
        req = self.conv.events.last_item(EV_REQUEST)
        resp = self.conv.entity.registration_endpoint(req)
        if resp.status == '200 OK' or resp.status == '201 Created':
            logging.debug('Registration response: {}'.format(resp.message))
            save_response(self.conv.events, resp,
                          oic.message.RegistrationResponse,
                          oic.message.ClientRegistrationErrorResponse)
        return resp


class AuthorizationResponse(Response):
    endpoint = 'authorization'

    def __init__(self, conv, inut, sh, **kwargs):
        Response.__init__(self, conv, inut, sh, **kwargs)
        try:
            self.op_type = kwargs['op_type']
        except KeyError:
            self.op_type = ''
        else:
            del kwargs['op_type']
        self.msg_args = kwargs

    def construct_message(self):
        _kwargs = {'request': self.conv.events.last_item(EV_REQUEST)}
        _kwargs.update(self.msg_args)
        _kwargs.update(self.op_args)

        _op = self.conv.entity
        try:
            _cookie = self.conv.events.last_item('Cookie')
        except NoSuchEvent:
            pass
        else:
            try:
                set_cookie(_op.server.cookiejar, SimpleCookie(_cookie))
            except CookieError as err:
                logger.error(err)
            else:
                _kwargs['cookie'] = _op.server._cookies()

        resp = _op.authorization_endpoint(**_kwargs)
        if isinstance(resp, SeeOther):
            save_response(self.conv.events, resp,
                          oic.message.AuthorizationResponse,
                          oic.message.AuthorizationErrorResponse)
        return resp


class AccessTokenResponse(Response):
    endpoint = 'token'

    def __init__(self, conv, inut, sh, **kwargs):
        Response.__init__(self, conv, inut, sh, **kwargs)
        try:
            self.op_type = kwargs['op_type']
        except KeyError:
            self.op_type = ''
        else:
            del kwargs['op_type']
        self.msg_args = kwargs

    def construct_message(self):
        _kwargs = {
            'request': self.conv.events.last_item(EV_REQUEST),
        }

        try:
            _kwargs['authn'] = self.conv.events.last_item('HTTP_AUTHORIZATION')
        except NoSuchEvent:
            pass

        _kwargs.update(self.msg_args)
        _kwargs.update(self.op_args)

        resp = self.conv.entity.token_endpoint(**_kwargs)
        save_response(self.conv.events, resp,
                      oic.message.AccessTokenResponse,
                      oic.message.TokenErrorResponse)
        return resp


class UserInfoResponse(Response):
    endpoint = 'userinfo'

    def __init__(self, conv, inut, sh, **kwargs):
        Response.__init__(self, conv, inut, sh, **kwargs)
        try:
            self.op_type = kwargs['op_type']
        except KeyError:
            self.op_type = ''
        else:
            del kwargs['op_type']
        self.msg_args = kwargs

    def construct_message(self):
        _kwargs = {'request': self.conv.events.last_item(EV_REQUEST)}
        try:
            _kwargs['authn'] = self.conv.events.last_item('HTTP_AUTHORIZATION')
        except NoSuchEvent:
            pass

        _kwargs.update(self.msg_args)
        _kwargs.update(self.op_args)

        resp = self.conv.entity.userinfo_endpoint(**_kwargs)
        save_response(self.conv.events, resp,
                      oic.message.OpenIDSchema,
                      oic.message.UserInfoErrorResponse)
        return resp


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj

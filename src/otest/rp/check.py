import inspect
import json
import sys
import requests

from future.backports.urllib.parse import urlparse

from otest.check import Check
from otest.check import ERROR
from otest.check import WARNING
from otest.events import EV_PROTOCOL_REQUEST
from otest.events import NoSuchEvent
from otest.shannon_entropy import calculate

from oic.oauth2 import AuthorizationRequest
from oic.oauth2 import AccessTokenRequest
from oic.extension.client import RegistrationRequest
from oic.oic import message

__author__ = 'roland'


def get_message(conv, classes):
    for msg_cls in classes:
        try:
            request = conv.events.get_message(EV_PROTOCOL_REQUEST, msg_cls)
        except NoSuchEvent:
            pass
        else:
            return request

    raise NoSuchEvent(classes)


def registration_request(conv):
    return get_message(conv, [RegistrationRequest, message.RegistrationRequest])


def authorization_request(conv):
    return get_message(conv, [AuthorizationRequest,
                              message.AuthorizationRequest])


def access_token_request(conv):
    return get_message(conv, [AccessTokenRequest,
                              message.AccessTokenRequest])


class VerifyRegistrationOfflineAccess(Check):
    cid = 'verify-registration-offline-access'
    msg = "Check if offline access is requested"

    def _func(self, conv):
        try:
            request = registration_request(conv)
        except NoSuchEvent:
            self._status = ERROR
        else:
            # 'offline_access only allow if response_type == 'code'
            try:
                req_scope = request['scope']
            except KeyError:
                pass
            else:
                if 'offline_access' in req_scope:
                    if request['response_type'] != 'code':
                        self._status = ERROR
                        self._message = 'Offline access not allowed for ' \
                                        'anything but code flow'

        return {}


class VerifyRegistrationResponseTypes(Check):
    cid = 'verify-registration-response_types'
    msg = "Only one of 'code' or 'token' allowed"

    def _func(self, conv):
        try:
            request = registration_request(conv)
        except NoSuchEvent:
            self._status = ERROR
        else:
            try:
                resp_types = request['response_types']
            except KeyError:
                pass
            else:
                try:
                    _allowed = self._kwargs['allowed']
                except KeyError:
                    if len(resp_types) > 1:
                        self._status = WARNING
                        self._message = 'Only allowed to register one ' \
                                        'response type'
                    elif resp_types[0] not in ['code', 'token']:
                        self._status = ERROR
                        self._message = 'Not allowed response type'
                else:
                    if not set(resp_types).issubset(set(_allowed)):
                        self._status = ERROR
                        self._message = \
                            'Asked for response_types not subset of {}'.format(
                                _allowed
                            )

        return {}


class VerifyRegistrationSoftwareStatement(Check):
    cid = 'verify-registration-software-statement'
    msg = "Verify that the correct claims appear in the Software statement"

    def _func(self, conv):
        try:
            request = registration_request(conv)
        except NoSuchEvent:
            self._status = ERROR
        else:
            try:
                _ss = request['software_statement']
            except KeyError:
                pass
            else:
                missing = []
                for claim in ['redirect_uris', 'grant_types', 'client_name',
                              'client_uri']:
                    if claim not in _ss:
                        missing.append(claim)
                if 'jwks_uri' not in _ss and 'jwks' not in _ss:
                    missing.append('jwks_uri/jwks')

                if missing:
                    self._status = WARNING
                    self._message = 'Missing "{}" claims from Software ' \
                                    'Statement'.format(missing)

        return {}


class VerifyRegistrationRedirectUriScheme(Check):
    cid = 'verify-registration-redirect_uri-scheme'
    msg = "Only certain redirect_uri schemes are allowed"

    def _func(self, conv):
        try:
            request = registration_request(conv)
        except NoSuchEvent:
            self._status = ERROR
        else:
            try:
                ruris = request['redirect_uris']
            except KeyError:
                self._status = ERROR
                self._message = 'MUST register redirect_uris'
            else:
                for ruri in ruris:
                    p = urlparse(ruri)
                    if p.scheme == 'https':
                        continue
                    elif p.scheme == 'http':
                        if 'localhost' != p.netloc.split('.'):
                            self._status = ERROR
                            self._message = 'Not allowed response type'
                            break
                    else:  # How do I check for local schemes ?
                        try:
                            uri_scheme = conv.data['uri_schemes']
                        except KeyError:
                            pass
                        else:
                            for scheme, desc in uri_scheme.items():
                                if p.scheme == scheme:
                                    self._status = WARNING
                                    self._message = \
                                        "None-local URI scheme: {}".format(
                                            scheme)
                                break

        return {}


class VerifyRegistrationPublicKeyRegistration(Check):
    cid = 'verify-registration-public_key-registration'
    msg = "Public key must be registered"

    def _func(self, conv):
        try:
            request = registration_request(conv)
        except NoSuchEvent:
            self._status = ERROR
        else:
            try:
                _uri = request['jwks_uri']
            except KeyError:
                try:
                    jwks = request['jwks']
                except KeyError:
                    self._status = ERROR
                    self._message = 'Must register a public key'
                else:
                    pub = 0
                    for desc in jwks['keys']:
                        if desc['kty'] in ['RSA', 'EC']:
                            pub += 1
                    if pub == 0:
                        self._status = ERROR
                        self._message = 'Must register a public key'
            else:
                resp = requests.request('GET', _uri, verify=False)
                if resp.status_code == 200:
                    jwks = json.loads(resp.text)
                    pub = 0
                    for desc in jwks['keys']:
                        if desc['kty'] in ['RSA', 'EC']:
                            pub += 1
                    if pub == 0:
                        self._status = ERROR
                        self._message = 'Must register a public key'
                else:
                    self._status = ERROR
                    self._message = 'Failed to access the RP keys at {}'.format(
                        _uri)

        return {}


class VerifyAuthorizationOfflineAccess(Check):
    cid = 'verify-authorization-offline-access'
    msg = "Check if offline access is requested"

    def _func(self, conv):
        try:
            request = registration_request(conv)
        except NoSuchEvent:
            self._status = ERROR
        else:
            try:
                req_scopes = request['scope']
            except KeyError:
                pass
            else:
                if 'offline_access' in req_scopes:
                    if request['response_type'] != ['code']:
                        self._status = ERROR
                        self._message = 'Offline access only when using ' \
                                        '"code" flow'

        return {}


class VerifyAuthorizationStateEntropy(Check):
    cid = 'verify-authorization-state-entropy'
    msg = "Check if offline access is requested"

    def _func(self, conv):
        try:
            request = authorization_request(conv)
        except NoSuchEvent:
            self._status = ERROR
            self._message = "No AuthorizationRequest"
        else:
            bits = calculate(request['state'])
            if bits < 128:
                self._status = WARNING
                self._message = 'Not enough entropy in string: {} < 128'.format(
                    bits)
        return {}


class VerifyAuthorizationRedirectUri(Check):
    cid = 'verify-authorization-redirect_uri'
    msg = "Check if offline access is requested"

    def _func(self, conv):
        try:
            clireq_request = registration_request(conv)
        except NoSuchEvent:
            self._status = ERROR
        else:
            try:
                authz_request = authorization_request(conv)
            except NoSuchEvent:
                self._status = ERROR
                self._message = 'No AuthorizationRequest'
            else:
                if authz_request['redirect_uri'] not in clireq_request[
                    'redirect_uris']:
                    self._status = ERROR
                    self._message = 'Redirect_uri not registered'

        return {}


class VerifyTokenRequestClientAssertion(Check):
    cid = 'verify-token-request-client_assertion'
    msg = "Check that the client_assertion JWT contains expected claims"

    def _func(self, conv):
        request = access_token_request(conv)

        ca = request['parsed_client_assertion']
        missing = []
        for claim in ["iss", "sub", "aud", "iat", "exp", "jti"]:
            if claim not in ca:
                missing.append(claim)

        if missing:
            self._status = ERROR
            self._message = 'Redirect_uri not registered'

        # verify jti entropy
        bits = calculate(ca['jti'])
        if bits < 128:
            self._status = WARNING
            self._message = 'Not enough entropy in string: {} < 128'.format(
                bits)

        return {}


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    from otest import check
    return check.factory(cid)

"""
    Assertion test module
    ~~~~~~~~~~~~~~~~~~~~~

    :copyright: (c) 2016 by Roland Hedberg.
    :license: APACHE 2.0, see LICENSE for more details.
"""
import json

from aatest.events import EV_PROTOCOL_RESPONSE
from aatest.events import EV_RESPONSE
from aatest.events import EV_REDIRECT_URL
from future.backports.urllib.parse import parse_qs

from oic.oic import message
from oic.oauth2 import AuthorizationRequest


def get_provider_info(conv):
    _pi = conv.entity.provider_info
    if not _pi:
        _pi = conv.provider_info
    return _pi


def get_protocol_response(conv, cls):
    return conv.events.get_messages(EV_PROTOCOL_RESPONSE, cls)


def get_id_tokens(conv):
    res = []
    # In access token responses
    for inst in get_protocol_response(conv, message.AccessTokenResponse):
        res.append(inst["id_token"])

    # implicit, id_token in authorization response
    for inst in get_protocol_response(conv, message.AuthorizationResponse):
        try:
            res.append(inst["id_token"])
        except KeyError:
            pass

    return res


def get_signed_id_tokens(conv):
    res = []
    for txt in conv.events.get_data(EV_RESPONSE):
        try:
            ent = json.loads(txt)
        except Exception:
            try:
                ent = parse_qs(txt)
            except:
                pass
            else:
                try:
                    res.append(ent['id_token'][0])
                except KeyError:
                    pass
        else:
            try:
                res.append(ent['id_token'])
            except KeyError:
                pass

    return res


def get_authorization_request(conv, cls):
    authz_req = conv.events.get_data(EV_REDIRECT_URL)[0].split('?')[1]
    return cls().from_urlencoded(authz_req)

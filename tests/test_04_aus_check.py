from oic.oic import AccessTokenResponse
from oic.oic import ProviderConfigurationResponse
from otest.aus.check import VerifyResponse, CheckHTTPResponse, CONT_JSON
from otest.check import ERROR, CRITICAL
from otest.check import OK
from otest.events import EV_PROTOCOL_RESPONSE, EV_HTTP_RESPONSE
from otest.test_setup import setup_conv


class Response(object):
    def __init__(self, **kwargs):
        for key, val in kwargs.items():
            setattr(self, key, val)


RESPONSE_200 = Response(status_code=200, headers={}, text='HTML text')
RESPONSE_400 = Response(status_code=400,
                        headers={'content-type': CONT_JSON},
                        text='{"error":"foo"}')


def test_verify_response():
    _info = setup_conv()
    _conv = _info['conv']

    # Add some reasonable responses

    atr = {
        "access_token":
            "ZDZjNWFmNzgtN2IxMi00YTY1LTk2NTEtODIyZjg5Ym",
        "expires_in": 7200,
        "id_token": {
            "at_hash": "fZlM5SoE8mdM80zBWSOzDQ",
            "aud": [
                "cb19ff50-6423-4955-92a2-73bea88796b4"
            ],
            "email": "johndoe@example.com",
            "exp": 1493066674,
            "iat": 1493059474,
            "iss": "https://guarded-cliffs-8635.herokuapp.com",
            "nonce": "WZ3PuYEnGxcM6ddf",
            "phone_number": "+49 000 000000",
            "phone_number_verified": False,
            "sid": "be99eccf-965f-4ba4-b0e4-39b0c26868e1",
            "sub": "9842f9ae-eb3c-4eba-8e4c-979ecae15fa1"
        },
        "token_type": "Bearer"
    }
    _conv.events.store(EV_PROTOCOL_RESPONSE, AccessTokenResponse(**atr))

    vr = VerifyResponse()
    vr._kwargs = {
        "response_cls": ["AccessTokenResponse", "AuthorizationResponse"]}
    res = vr._func(_conv)
    assert res == {}
    assert vr._status == OK


def test_verify_response_missing():
    _info = setup_conv()
    _conv = _info['conv']

    # Add responses
    _conv.events.store(
        EV_PROTOCOL_RESPONSE,
        ProviderConfigurationResponse(
            issuer='https://example.com',
            authorization_endpoint='https://example.com/authz',
            jwks_uri = 'https://example.com/jwks.json',
            subject_types_supported=['public'],
            id_token_signing_alg_values_supported=['RS256']
        ))

    vr = VerifyResponse()
    vr._kwargs = {
        "response_cls": ["AccessTokenResponse", "AuthorizationResponse"]}
    res = vr._func(_conv)
    assert res == {}
    assert vr._status == ERROR


def test_check_http_response_200():
    _info = setup_conv()
    _conv = _info['conv']

    _conv.events.store(EV_HTTP_RESPONSE, RESPONSE_200)
    _conv.events.store(
        EV_PROTOCOL_RESPONSE,
        ProviderConfigurationResponse(
            issuer='https://example.com',
            authorization_endpoint='https://example.com/authz',
            jwks_uri = 'https://example.com/jwks.json',
            subject_types_supported=['public'],
            id_token_signing_alg_values_supported=['RS256']
        ))

    cr = CheckHTTPResponse()
    res = cr._func(_conv)
    assert res == {}
    assert cr._status == OK


def test_check_http_response_4xx():
    _info = setup_conv()
    _conv = _info['conv']

    _conv.events.store(EV_HTTP_RESPONSE, RESPONSE_400)
    _conv.events.store(
        EV_PROTOCOL_RESPONSE,
        ProviderConfigurationResponse(
            issuer='https://example.com',
            authorization_endpoint='https://example.com/authz',
            jwks_uri = 'https://example.com/jwks.json',
            subject_types_supported=['public'],
            id_token_signing_alg_values_supported=['RS256']
        ))

    cr = CheckHTTPResponse()
    res = cr._func(_conv)
    assert res == {'content': '{"error":"foo"}', 'http_status': 400, 'url': ''}
    assert cr._status == CRITICAL

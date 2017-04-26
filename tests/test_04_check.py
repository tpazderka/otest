from otest.aus.check import VerifyResponse
from otest.test_setup import setup_conv


def test_verify_response():
    _info = setup_conv()
    _conv = _info['conv']
    vr = VerifyResponse()
    vr._kwargs = {
        "response_cls": ["AccessTokenResponse", "AuthorizationResponse"]}
    res = vr._func(_conv)
    assert res

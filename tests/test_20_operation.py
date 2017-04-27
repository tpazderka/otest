from oic.exception import MissingAttribute
from oic.oauth2 import ErrorResponse
from oic.oic import AccessTokenResponse
from oic.oic import AuthorizationResponse
from otest import Operation, Break
from otest.events import EV_EVENT
from otest.test_setup import setup_conv


def authorization_response():
    return AuthorizationResponse(code='code', state='state')


def access_token_response():
    return AccessTokenResponse(access_token='token', token_type='foobar')


def func_exception():
    raise MissingAttribute('foo')


def func_error(error, error_description=''):
    return ErrorResponse(error=error, error_description=error_description)


def func_text():
    return 'random letters ..'


def test_operation_expected_instance():
    _info = setup_conv()
    _conv = _info['conv']
    op = Operation(_conv, _info['io'], _info['io'].session, test_id='1')
    op.message_cls = AuthorizationResponse

    s = op.catch_exception_and_error(authorization_response)
    assert s


def test_operation_unexpected_instance():
    _info = setup_conv()
    _conv = _info['conv']
    op = Operation(_conv, _info['io'], _info['io'].session, test_id='1')
    op.message_cls = AuthorizationResponse

    try:
        op.catch_exception_and_error(access_token_response)
    except Break:
        assert True
    else:
        assert False


def test_operation_expected_exception():
    _info = setup_conv()
    _conv = _info['conv']
    op = Operation(_conv, _info['io'], _info['io'].session, test_id='1')
    op.message_cls = AuthorizationResponse
    op.expect_exception = 'MissingAttribute'

    s = op.catch_exception_and_error(func_exception)
    assert s is None


def test_operation_unexpected_exception():
    _info = setup_conv()
    _conv = _info['conv']
    op = Operation(_conv, _info['io'], _info['io'].session, test_id='1')
    op.message_cls = AuthorizationResponse
    op.expect_exception = 'MissingParameter'

    try:
        op.catch_exception_and_error(func_exception)
    except Exception:
        assert True
    else:
        assert False


def test_operation_expected_error():
    _info = setup_conv()
    _conv = _info['conv']
    op = Operation(_conv, _info['io'], _info['io'].session, test_id='1')
    op.message_cls = AuthorizationResponse
    op.expect_error = {'error': ["invalid_request",
                                 "unauthorized_client",
                                 "access_denied",
                                 "unsupported_response_type",
                                 "invalid_scope", "server_error",
                                 "temporarily_unavailable"]}

    s = op.catch_exception_and_error(func_error, error='unauthorized_client')
    assert s


def test_operation_unexpected_error():
    _info = setup_conv()
    _conv = _info['conv']
    op = Operation(_conv, _info['io'], _info['io'].session, test_id='1')
    op.message_cls = AuthorizationResponse
    op.expect_error = {'error': ["invalid_request",
                                 "unauthorized_client",
                                 "access_denied",
                                 "unsupported_response_type",
                                 "invalid_scope", "server_error",
                                 "temporarily_unavailable"]}

    s = op.catch_exception_and_error(func_error, error='invalid_client')
    assert s
    _ev = _conv.events.get(EV_EVENT)
    assert len(_ev) == 1
    assert _ev[0].data.startswith('Expected error not received')


def test_operation_other():
    _info = setup_conv()
    _conv = _info['conv']
    op = Operation(_conv, _info['io'], _info['io'].session, test_id='1')
    op.message_cls = AuthorizationResponse

    s = op.catch_exception_and_error(func_text)
    assert s

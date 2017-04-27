from oidctest.op import func
from oidctest.op import oper
from oidctest.op.client import Client
from oidctest.session import SessionHandler

from otest.aus.handling_ph import WebIh
from otest.conf_setup import OP_ORDER
from otest.conversation import Conversation
from otest.events import Events
from otest.flow import FlowState
from otest.prof_util import ProfileHandler

from oic.oic.message import factory
from oic.oic.message import ProviderConfigurationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD


def setup_conv():
    entity = Client(client_authn_method=CLIENT_AUTHN_METHOD,
                    verify_ssl=False)
    entity.provider_info = ProviderConfigurationResponse(
        authorization_endpoint="https://example.com",
    )

    cls_factories = {'': oper.factory}
    func_factory = func.factory

    flow_state = FlowState('flows', profile_handler=ProfileHandler,
                           cls_factories=cls_factories,
                           func_factory=func_factory,
                           display_order=OP_ORDER)
    iss = 'https://example.org'
    tag = 'foobar'
    session_handler = SessionHandler(iss, tag,
                                     flows=flow_state,
                                     tool_conf={})  # , rest=rest, **webenv)
    session_handler.iss = iss
    session_handler.tag = tag

    info = WebIh(session=session_handler, profile_handler=ProfileHandler)

    conv = Conversation([], entity, factory, callback_uris=[])
    conv.events = Events()
    conv.tool_config = {}
    return {'conv': conv, 'io': info}

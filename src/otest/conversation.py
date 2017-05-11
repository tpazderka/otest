import json
import logging
#from otest.interaction import Interaction
from otest.events import Events

__author__ = 'roland'

logger = logging.getLogger(__name__)


class Conversation(object):
    def __init__(self, flow, entity, msg_factory, check_factory=None,
                 features=None, opid=None, **extra_args):
        self.flow = flow
        self.entity = entity
        self.msg_factory = msg_factory
        self.events = Events()
        #self.interaction = Interaction(self.entity, interaction)
        self.check_factory = check_factory
        self.features = features
        self.operator_id = opid
        self.extra_args = extra_args
        self.test_id = ""
        self.info = {}
        self.index = 0
        self.comhandler = None
        self.exception = None
        self.sequence = []
        self.cache = {}
        self.tool_config = {}
        self.conf = None

    def dump_state(self, filename):
        state = {
            "client": {
                "behaviour": self.entity.behaviour,
                "keyjar": self.entity.keyjar.dump(),
                "provider_info": self.entity.provider_info.to_json(),
                "client_id": self.entity.client_id,
                "client_secret": self.entity.client_secret,
            },
            "sequence": self.flow,
            "flow_index": self.index,
            "client_config": self.entity.conf,
            "condition": self.events.get('condition')
        }

        try:
            state["client"][
                "registration_resp"] = \
                self.entity.registration_response.to_json()
        except AttributeError:
            pass

        txt = json.dumps(state)
        _fh = open(filename, "w")
        _fh.write(txt)
        _fh.close()

    def get_tool_attribute(self, *attr, **kwargs):
        """
        Return the tool configuration attribute value.
        If more then one attribute is specified, first try the first one
        if that doesn'e succeed take try the next one and so on.

        :param attr: A list of attributes
        :param default: If none of the attributes have a value return this
        :return: An attribute value or the default value. If no attribute 
        value or default value raise KeyError.
        """
        for claim in attr:
            try:
                return self.tool_config[claim]
            except KeyError:
                pass

        return kwargs['default']

    def get_redirect_uris(self):
        try:
            return self.entity.registration_response["redirect_uris"]
        except KeyError:
            try:
                return self.entity.registration_info["redirect_uris"]
            except KeyError:
                try:
                    return self.conf.CLIENT['registration_info'][
                        "redirect_uris"]
                except KeyError:
                    return self.conf.CLIENT['registration_response'][
                        "redirect_uris"]

import copy
import logging

from otest import Done
from otest.parse_cnf import sort

__author__ = 'roland'

logger = logging.getLogger(__name__)


def pmap(sprof, prof):
    try:
        p = sprof.split('.')
    except AttributeError:
        p = sprof

    try:
        rt = prof.split('.')
    except AttributeError:
        rt = prof

    if rt[0] == '*' or p[0] in rt:
        return True
    else:
        return False


class Node(object):
    def __init__(self, name, desc, mti=None):
        self.name = name
        self.desc = desc
        self.mti = mti
        self.state = 0
        self.info = ""
        self.rmc = False
        self.experr = False
        self.complete = False


class SessionHandler(object):
    def __init__(self, flows=None, order=None, tool_version='', **kwargs):
        self.test_flows = flows
        self.order = order
        self.extra = kwargs
        self.tool_version = tool_version
        self._dict = {}

    @property
    def profile(self):
        return self.extra['profile']

    def session_setup(self, path="", flow=None, index=0):
        logger.info("session_setup")

        _keys = list(self.keys())
        for key in _keys:
            if key in ["tests", "flow_names", "response_type",
                       "test_info", "profile", 'test_conf', 'sid']:
                continue
            else:
                del self[key]

        self["testid"] = path
        if not flow:
            flow = self.test_flows.expanded_conf(path)

        self['flow'] = flow
        self["sequence"] = self["flow"]["sequence"]
        self["sequence"].append(Done)
        self["index"] = index

    def init_session(self, profile=None):
        if profile is None:
            profile = self.profile

        self["tests"] = self.test_flows.matches_profile(profile)
        return self._dict

    def reset_session(self, profile=None):
        _keys = list(self.keys())
        for key in _keys:
            if key.startswith("_"):
                continue
            else:
                del self[key]
        self.init_session(profile)

    def session_init(self):
        if "tests" not in self or self['tests'] == []:
            self.init_session()
            return True
        else:
            return False

    def dump(self, filename):
        pass

    def load(self, filename):
        pass

    def keys(self):
        return self._dict.keys()

    def update(self, new):
        self._dict.update(new)

    def __delitem__(self, item):
        del self._dict[item]

    def __getitem__(self, item):
        return self._dict[item]

    def __setitem__(self, key, value):
        self._dict[key] = value

    def __contains__(self, item):
        return item in self._dict

    def items(self):
        return self._dict.items()

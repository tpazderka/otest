import time
from oic import rndstr
from otest.conversation import Conversation

__author__ = 'roland'


class Instances(object):
    def __init__(self, as_args, baseurl, profiles, provider_cls, **kwargs):
        self._db = {}
        self.as_args = as_args
        self.base_url = baseurl
        self.profile = profiles
        self.provider_cls = provider_cls

        self.profiles = ['default']
        self.profiles.extend(list(profiles.keys()))
        self.profiles.append('custom')
        self.data = kwargs

    def remove_old(self):
        now = time.time()

        for key, val in self._db.items():
            if now - val['ts'] > 43200:
                del self._db[key]

    def new_map(self, sid=''):
        if not sid:
            sid = rndstr(16)

        op = self.provider_cls(**self.as_args)

        op.baseurl = '{}{}'.format(self.base_url, sid)
        op.name = op.baseurl

        _conv = Conversation(None, op, None)
        _conv.events = self.as_args['event_db']
        _conv.data = self.data
        op.trace = _conv.trace

        self._db[sid] = {
            'op': op,
            'conv': _conv,
            'ts': time.time(),
            'selected': {}
        }

        return sid

    def __getitem__(self, item):
        return self._db[item]

    def __setitem__(self, key, value):
        self._db[key] = value


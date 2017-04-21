from oic import oic
from oic.extension import client
from oic.oic import RegistrationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from otest.events import EV_RESPONSE
from otest.events import EV_PROTOCOL_RESPONSE

__author__ = 'roland'


class OicClient(oic.Client):
    def __init__(self, *args, **kwargs):
        oic.Client.__init__(self, *args, **kwargs)
        self.conv = None

    def store_response(self, clinst, text):
        self.conv.events.store(EV_RESPONSE, text)
        self.conv.events.store(EV_PROTOCOL_RESPONSE, clinst)


class ExtClient(client.Client):
    def __init__(self, *args, **kwargs):
        client.Client.__init__(self, *args, **kwargs)
        self.conv = None

    def store_response(self, clinst, text):
        self.conv.events.store(EV_RESPONSE, text)
        self.conv.events.store(EV_PROTOCOL_RESPONSE, clinst)


class Factory(object):
    def __init__(self, client_cls):
        self.client_cls = client_cls

    def make_client(self, **kw_args):
        """
        Have to get own copy of keyjar

        :param kw_args:
        :return:
        """
        c_keyjar = kw_args["keyjar"].copy()
        args = {'client_authn_method': CLIENT_AUTHN_METHOD, 'keyjar': c_keyjar}
        try:
            args['verify_ssl'] = kw_args['verify_ssl']
        except KeyError:
            pass
        else:
            c_keyjar.verify_ssl = kw_args['verify_ssl']

        _cli = self.client_cls(**args)

        c_info = {'keyjar': c_keyjar}
        for arg, val in list(kw_args.items()):
            if arg in ['keyjar']:
                continue
            setattr(_cli, arg, val)
            if arg == 'provider_info':
                _cli.handle_provider_config(val, val['issuer'])
            elif arg == 'registration_response':
                resp = RegistrationResponse(**val)
                _cli.store_registration_info(resp)
            c_info[arg] = val

        return _cli, c_info

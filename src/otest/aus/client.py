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

    def adjust_kid(self, kidd, keyjar):
        """
        Verify that the set of keys assigned to different usage is still
        around.
        
        :param kidd: Dictionary {usage: {key_type: kid}} 
        :param keyjar:  A KeyJar instance
        :return: A corrected kid dictionary
        """
        res = {}
        for usage, spec in kidd.items():
            res[usage] = {}
            for key_type, _id in spec.items():
                if not keyjar.get(usage, key_type, kid=_id):
                    l = keyjar.get(usage, key_type)
                    if l:
                        res[usage][key_type] = l[0].kid
                else:
                    res[usage][key_type] = _id
        return res

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

        try:
            _kid = kw_args['kid']
        except KeyError:
            pass
        else:
            kw_args['kid'] = self.adjust_kid(_kid, _cli.keyjar)

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

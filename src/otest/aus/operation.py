import functools
import inspect
import json
import logging
import os
import sys
import time

from Cryptodome.PublicKey import RSA
from future.backports.urllib.parse import urlparse
from jwkest.jwk import RSAKey
from oic.oauth2.message import Message
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import dump_jwks
from oic.utils.keyio import ec_init
from otest import RequirementsNotMet
from otest import Unknown
from otest import operation
from otest.aus.request import SyncGetRequest
from otest.operation import request_with_client_http_session

__author__ = 'roland'

logger = logging.getLogger(__name__)


def include(url, test_id):
    p = urlparse(url)
    if p.path[1:].startswith(test_id):
        if len(p.path[1:].split("/")) <= 1:
            return os.path.join(url, "_/_/_/normal")
        else:
            return url

    return "%s://%s/%s%s_/_/_/normal" % (p.scheme, p.netloc, test_id, p.path)


def get_id_token(responses):
    """
    Find the id_tokens issued, last one first in the list
    :param responses: A list of Response instance, text message tuples
    :return: list of IdTokens instances
    """
    res = []
    for resp, txt in responses:
        try:
            res.insert(0, resp["id_token"])
        except KeyError:
            pass
    return res


class Operation(operation.Operation):
    message_cls = Message

    def __init__(self, conv, inut, sh, test_id='', conf=None,
                 funcs=None, check_factory=None, cache=None, profile='',
                 tool_conf=None):
        operation.Operation.__init__(self, conv, inut, sh, test_id,
                                     conf, funcs, check_factory, cache,
                                     tool_conf)

        try:
            self.profile = profile.split('.')
        except AttributeError:
            self.profile = profile

        # Monkey-patch: make sure we use the same http session (preserving
        # cookies) when fetching keys from issuers 'jwks_uri' as for the
        # rest of the test sequence
        import oic.utils.keyio

        oic.utils.keyio.request = functools.partial(
            request_with_client_http_session, self)


class UpdateProviderKeys(Operation):
    def __call__(self, *args, **kwargs):
        issuer = self.conv.entity.provider_info["issuer"]
        # Update all keys
        for keybundle in self.conv.entity.keyjar.issuer_keys[issuer]:
            keybundle.update()


class RotateKey(Operation):
    def __call__(self):
        keyjar = self.conv.entity.keyjar
        self.conv.entity.original_keyjar = keyjar.copy()

        # invalidate the old key
        old_kid = self.op_args["old_kid"]
        old_key = keyjar.get_key_by_kid(old_kid)
        old_key.inactive_since = time.time()

        # setup new key
        key_spec = self.op_args["new_key"]
        typ = key_spec["type"].upper()
        if typ == "RSA":
            kb = KeyBundle(keytype=typ, keyusage=key_spec["use"])
            kb.append(RSAKey(use=key_spec["use"]).load_key(
                RSA.generate(key_spec["bits"])))
        elif typ == "EC":
            kb = ec_init(key_spec)
        else:
            raise Exception('Wrong key type')

        # add new key to keyjar with
        list(kb.keys())[0].kid = self.op_args["new_kid"]
        keyjar.add_kb("", kb)

        # make jwks and update file
        keys = []
        for kb in keyjar[""]:
            keys.extend(
                [k.to_dict() for k in list(kb.keys()) if not k.inactive_since])
        jwks = dict(keys=keys)
        with open(self.op_args["jwks_path"], "w") as f:
            f.write(json.dumps(jwks))


class RestoreKeyJar(Operation):
    def __call__(self):
        self.conv.entity.keyjar = self.conv.entity.original_keyjar

        # make jwks and update file
        keys = []
        for kb in self.conv.entity.keyjar[""]:
            keys.extend([k.to_dict() for k in list(kb.keys())])
        jwks = dict(keys=keys)
        with open(self.op_args["jwks_path"], "w") as f:
            f.write(json.dumps(jwks))


class ReadRegistration(SyncGetRequest):
    def op_setup(self):
        _client = self.conv.entity
        self.req_args["access_token"] = _client.registration_access_token
        self.op_args["authn_method"] = "bearer_header"
        self.op_args["endpoint"] = _client.registration_response[
            "registration_client_uri"]


class FetchKeys(Operation):
    def __call__(self):
        kb = KeyBundle(source=self.conv.entity.provider_info["jwks_uri"])
        kb.verify_ssl = False
        kb.update()

        try:
            self.conv.keybundle.append(kb)
        except AttributeError:
            self.conv.keybundle = [kb]


class RotateKeys(Operation):
    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.jwk_name = "export/jwk.json"
        self.new_key = {}
        self.kid_template = "_%d"
        self.key_usage = ""

    def __call__(self):
        # find the name of the file to which the JWKS should be written
        try:
            _uri = self.conv.entity.registration_response["jwks_uri"]
        except KeyError:
            raise RequirementsNotMet("No dynamic key handling")

        r = urlparse(_uri)
        # find the old key for this key usage and mark that as inactive
        for kb in self.conv.entity.keyjar.issuer_keys[""]:
            for key in list(kb.keys()):
                if key.use in self.new_key["use"]:
                    key.inactive = True

        kid = 0
        # only one key
        _nk = self.new_key
        _typ = _nk["type"].upper()

        if _typ == "RSA":
            kb = KeyBundle(source="file://%s" % _nk["key"],
                           fileformat="der", keytype=_typ,
                           keyusage=_nk["use"])
        else:
            kb = {}

        for k in list(kb.keys()):
            k.serialize()
            k.kid = self.kid_template % kid
            kid += 1
            self.conv.entity.kid[k.use][k.kty] = k.kid
        self.conv.entity.keyjar.add_kb("", kb)

        dump_jwks(self.conv.entity.keyjar[""], r.path[1:])


class RotateSigKeys(RotateKeys):
    def __init__(self, conv, inut, sh, **kwargs):
        RotateKeys.__init__(self, conv, inut, sh, **kwargs)
        self.new_key = {"type": "RSA", "key": "./keys/second_sig.key",
                        "use": ["sig"]}
        self.kid_template = "sig%d"


class RotateEncKeys(RotateKeys):
    def __init__(self, conv, inut, sh, **kwargs):
        RotateKeys.__init__(self, conv, inut, sh, **kwargs)
        self.new_key = {"type": "RSA", "key": "./keys/second_enc.key",
                        "use": ["enc"]}
        self.kid_template = "enc%d"


class Cache(Operation):
    pass


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj

    from otest import operation

    obj = operation.factory(name)
    if not obj:
        raise Unknown("Couldn't find the operation: '{}'".format(name))
    return obj

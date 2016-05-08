import json
import logging
import csv
import pkg_resources

from aatest.events import Events
from oic.extension.token import JWTToken

from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import keyjar_init
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo

from otest.rp.provider import Provider

logger = logging.getLogger(__name__)

__author__ = 'roland'


def read_uri_schemes(filename):
    csvfile = open(filename, 'r')
    l = csvfile.readline()
    l = l.strip()
    fieldnames = l.split(',')
    reader = csv.DictReader(csvfile, fieldnames)
    return dict(
        [(r['URI Scheme'], '{} {}'.format(r['Description'], r['Reference'])) for
         r in reader])


def as_arg_setup(args, lookup, config):
    try:
        _issuer = config.issuer % args.port
    except TypeError:
        _issuer = config.issuer % int(args.port)

    # Client data base
    # cdb = shelve.open(config.CLIENT_DB, writeback=True)
    cdb = {}

    ac = AuthnBroker()

    for authkey, value in list(config.AUTHENTICATION.items()):
        authn = None
        # if "UserPassword" == authkey:
        #     from oic.utils.authn.user import UsernamePasswordMako
        #     authn = UsernamePasswordMako(None, "login.mako", LOOKUP, PASSWD,
        #                                  "authorization")

        if "NoAuthn" == authkey:
            from oic.utils.authn.user import NoAuthn

            authn = NoAuthn(None, user=config.AUTHENTICATION[authkey]["user"])

        if authn is not None:
            ac.add(config.AUTHENTICATION[authkey]["ACR"], authn,
                   config.AUTHENTICATION[authkey]["WEIGHT"])

    # dealing with authorization
    authz = AuthzHandling()

    if config.USERINFO == "SIMPLE":
        # User info is a simple dictionary in this case statically defined in
        # the configuration file
        userinfo = UserInfo(config.USERDB)
    else:
        userinfo = None

    as_args = {
        "name": _issuer,
        "cdb": cdb,
        "authn_broker": ac,
        "userinfo": userinfo,
        "authz": authz,
        "client_authn": verify_client,
        "symkey": config.SYM_KEY,
        "template_lookup": lookup,
        "template": {"form_post": "form_response.mako"},
        "jwks_name": "./static/jwks_{}.json",
        'event_db': Events(),
    }

    try:
        as_args['behavior'] = config.BEHAVIOR
    except AttributeError:
        pass

    com_args = {
        "baseurl": config.baseurl,
    }

    for arg in ['name', 'cdb', 'authn_broker', 'userinfo', 'authz', 'template',
                'jwks_name', 'client_authn', 'symkey', 'template_lookup']:
        com_args[arg] = as_args[arg]

    # Add own keys for signing/encrypting JWTs
    try:
        # a throw-away OP used to do the initial key setup
        _op = Provider(sdb=SessionDB(com_args["baseurl"]), **com_args)
        jwks = keyjar_init(_op, config.keys)
    except KeyError:
        key_arg = {}
    else:
        key_arg = {"jwks": jwks, "keys": config.keys}
        as_args['jwks_name'] = 'static/jwks.json'
        f = open('static/jwks.json', 'w')
        f.write(json.dumps(jwks))
        f.close()

        if args.insecure:
            _op.keyjar.verify_ssl = False
        else:
            _op.keyjar.verify_ssl = True

        as_args['keyjar'] = _op.keyjar
        as_args['sdb'] = SessionDB(
            com_args["baseurl"],
            token_factory=JWTToken('T', keyjar=_op.keyjar,
                                   lt_pattern={'code': 3600, 'token': 900},
                                   iss=com_args['baseurl'],
                                   sign_alg='RS256'),
            refresh_token_factory=JWTToken(
                'R', keyjar=_op.keyjar, lt_pattern={'': 24 * 3600},
                iss=com_args['baseurl'])
        )

    return as_args, key_arg


def main_setup(args, lookup, config):
    config.issuer = config.issuer % args.port
    config.SERVICE_URL = config.SERVICE_URL % args.port

    as_args, key_arg = as_arg_setup(args, lookup, config)

    kwargs = {
        "template_lookup": lookup,
        "template": {"form_post": "form_response.mako"},
    }

    # Should I care about verifying the certificates used by other entities
    if args.insecure:
        kwargs["verify_ssl"] = False
    else:
        kwargs["verify_ssl"] = True

    op_arg = key_arg

    try:
        op_arg["cookie_ttl"] = config.COOKIETTL
    except AttributeError:
        pass

    try:
        op_arg["cookie_name"] = config.COOKIENAME
    except AttributeError:
        pass

    # print URLS
    if args.debug:
        op_arg["debug"] = True

    # # All endpoints the OpenID Connect Provider should answer on
    # add_endpoints(ENDPOINTS)
    # op_arg["endpoints"] = ENDPOINTS

    if args.port == 80:
        _baseurl = config.baseurl
    else:
        if config.baseurl.endswith("/"):
            config.baseurl = config.baseurl[:-1]
        _baseurl = "%s:%d" % (config.baseurl, args.port)

    if not _baseurl.endswith("/"):
        _baseurl += "/"

    op_arg["baseurl"] = _baseurl

    logger.info('setup kwargs: {}'.format(kwargs))

    try:
        op_arg["marg"] = multi_keys(as_args, config.multi_keys)
    except AttributeError as err:
        pass

    op_arg['uri_schemes'] = read_uri_schemes(
        pkg_resources.resource_filename('otest', 'uri-schemes-1.csv'))

    if args.op_profiles:
        profiles = {}
        for p in args.op_profiles:
            profiles.update(json.loads(open(p).read()))
    else:
        profiles = {}

    op_arg['profiles'] = profiles

    logger.info("setup as_args: {}".format(as_args))
    logger.info(" --   op_arg: {}".format(op_arg))

    return as_args, op_arg, config


def multi_keys(as_args, key_conf):
    # a throw-away OP used to do the initial key setup
    _op = Provider(**as_args)
    jwks = keyjar_init(_op, key_conf, "m%d")

    return {"jwks": jwks, "keys": key_conf}

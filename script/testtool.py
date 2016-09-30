#!/usr/bin/env python3
import importlib
import json
import logging
import os
import sys
import requests
import traceback

from os import listdir
from os.path import isdir
from os.path import isfile
from os.path import join

from future.backports.urllib.parse import parse_qs

from mako.lookup import TemplateLookup

from oic import rndstr
from oic.utils.http_util import extract_from_request
from oic.utils.http_util import get_or_post
from oic.utils.http_util import NotFound
from oic.utils.http_util import Response
from oic.utils.http_util import ServiceError
from oic.utils.http_util import SeeOther
from oic.utils import http_util

from otest import Trace
from otest.events import Events
from otest.events import EV_REQUEST
from otest.events import EV_RESPONSE
from otest.parse_cnf import parse_yaml_conf
from otest.session import SessionHandler
from otest.rp.endpoints import static_mime
from otest.rp.io import WebIO
from otest.rp.setup import as_arg_setup
from otest.rp.tool import WebTester

__author__ = 'roland'

logger = logging.getLogger("")
LOGFILE_NAME = 'tt.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

ROOT = './'

LOOKUP = TemplateLookup(directories=[ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')


class JLog(object):
    def __init__(self, logger, sid):
        self.logger = logger
        self.id = sid

    def info(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.info(json.dumps(_dict))

    def debug(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.debug(json.dumps(_dict))

    def exception(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.exception(json.dumps(_dict))

    def error(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.error(json.dumps(_dict))

    def warning(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.warning(json.dumps(_dict))


def css(environ, event_db):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except (OSError, IOError):
        resp = NotFound(environ["PATH_INFO"])

    return resp


def start_page(environ, start_response, target):
    msg = open('start_page.html').read().format(target=target)
    resp = Response(msg)
    return resp(environ, start_response)


def make_entity(provider_cls, **as_args):
    return provider_cls(**as_args)


# =============================================================================


class Application(object):
    def __init__(self, base_url, **kwargs):
        self.base_url = base_url
        self.kwargs = kwargs
        self.events = Events()
        self.endpoints = {}
        self.session_conf = {}

    def store_response(self, response):
        self.events.store(EV_RESPONSE, response.info())

    def wsgi_wrapper(self, environ, func, **kwargs):
        kwargs = extract_from_request(environ, kwargs)
        self.events.store(EV_REQUEST, kwargs)
        args = func(**kwargs)

        try:
            resp, state = args
            self.store_response(resp)
            return resp
        except TypeError:
            resp = args
            self.store_response(resp)
            return resp
        except Exception as err:
            logger.error("%s" % err)
            raise

    def handle(self, environ, tester, sid, path, qs=''):
        _sh = tester.sh
        if qs:
            msg = qs
        else:
            try:
                msg = get_or_post(environ)
            except AttributeError:
                msg = {}

        filename = self.kwargs['profile_handler'](_sh).log_path(
            sid=sid, test_id=_sh['conv'].test_id)

        _sh['conv'].entity_id = sid
        return tester.do_next(msg, filename,
                              profile_handler=self.kwargs['profile_handler'],
                              path=path)

    @staticmethod
    def pick_grp(name):
        return name.split('-')[1]

    # publishes the OP endpoints
    def application(self, environ, start_response):
        session = environ['beaker.session']

        jlog = JLog(logger, session.id)
        path = environ.get('PATH_INFO', '').lstrip('/')
        jlog.info({"remote_addr": environ["REMOTE_ADDR"],
                   "path": path})
        self.events.store(EV_REQUEST, path)

        try:
            sh = session['session_info']
        except KeyError:
            sh = SessionHandler(**self.kwargs)
            sh.session_init()
            session['session_info'] = sh

        inut = WebIO(session=sh, **self.kwargs)
        inut.environ = environ
        inut.start_response = start_response

        tester = WebTester(inut, sh, **self.kwargs)

        if 'path' in self.kwargs and path.startswith(self.kwargs['path']):
            _path = path[len(kwargs['path']) + 1:]
        else:
            _path = path

        if _path == "robots.txt":
            return static_mime("static/robots.txt", environ, start_response)
        elif _path.startswith("static/"):
            return static_mime(_path, environ, start_response)
        elif _path == "list":
            try:
                qs = parse_qs(get_or_post(environ))
            except Exception as err:
                jlog.error({'message': err})
            else:
                if qs:
                    sh['test_conf'] = dict([(k, v[0]) for k, v in qs.items()])
                    # self.session_conf[sh['sid']] = sh

            res = tester.display_test_list()
            return res
        elif _path == '' or _path == 'config':
            sid = 'AAAAA'
            try:
                args = sh['test_conf']
            except:
                args = {}
            # self.session_conf[sid] = sh
            # session['session_info'] = sh
            return tester.do_config(sid, **args)
        elif _path in self.kwargs['flows'].keys():  # Run flow
            # Will use the same test configuration
            try:
                _ = tester.sh['test_conf']
            except KeyError:
                resp = SeeOther('/')
                return resp(environ, start_response)
            # But will create a new OP
            _sid = rndstr(24)
            tester.sh['sid'] = _sid
            self.session_conf[_sid] = sh

            resp = tester.run(_path, sid=_sid, **self.kwargs)
            if resp:
                logger.info(
                    'Response class: {}'.format(resp.__class__.__name__))

            if isinstance(resp, requests.Response):
                try:
                    loc = resp.headers['location']
                except KeyError:
                    logger.info(
                        'Response type: {}, missing location'.format(
                            type(resp)))
                    resp = ServiceError(
                        'Wrong response: {}'.format(resp.status_code))
                else:
                    # tester.conv.events.store('Cookie', resp.headers[
                    # 'set-cookie'])
                    if loc.startswith(tester.base_url):
                        _path = loc[len(tester.base_url):]
                        if _path[0] == '/':
                            _path = _path[1:]
                    resp = SeeOther(loc)
                return resp(environ, start_response)
            elif resp is True or resp is False or resp is None:
                return tester.display_test_list()
            else:
                return resp(environ, start_response)
        elif _path == 'display':
            return inut.flow_list()
        elif _path == "opresult":
            try:
                _display_path = '/{}/display'.format(self.kwargs['path'])
            except KeyError:
                _display_path = '/display'
            resp = SeeOther(
                "{}#{}".format(_display_path,
                               self.pick_grp(sh['conv'].test_id)))
            return resp(environ, start_response)
        elif _path.startswith("test_info"):
            p = _path.split("/")
            try:
                return inut.test_info(p[1])
            except KeyError:
                return inut.not_found()
        elif _path == 'all':
            for test_id in sh['flow_names']:
                resp = tester.run(test_id, **self.kwargs)
                if resp is True or resp is False:
                    continue
                elif resp:
                    return resp(environ, start_response)
                else:
                    resp = ServiceError('Unkown service error')
                    return resp(environ, start_response)
            return tester.display_test_list()

        # Whatever gets here should be of the form <session_id>/<path>
        try:
            sid, _path = _path.split('/', 1)
        except ValueError:
            pass
        else:
            if _path.startswith("static/"):
                return static_mime(_path, environ, start_response)

            try:
                _sh = self.session_conf[sid]
            except KeyError:
                resp = ServiceError("Unknown session")
                return resp(environ, start_response)

            tester.sh = _sh
            if 'HTTP_AUTHORIZATION' in environ:
                _sh['conv'].events.store('HTTP_AUTHORIZATION',
                                         environ['HTTP_AUTHORIZATION'])
            _p = _path.split('?')
            if _p[0] in _sh['conv'].entity.endpoints():
                resp = self.handle(environ, tester, sid, *_p)
                self.session_conf[sid] = tester.sh
                return resp(environ, start_response)

            for endpoint, service in self.endpoints.items():
                if _path == endpoint:
                    jlog.info({"service": service})
                    try:
                        resp = self.handle(environ, tester, sid, service)
                        return resp(environ, start_response)
                    except Exception as err:
                        print("%s" % err)
                        message = traceback.format_exception(*sys.exc_info())
                        print(message)
                        jlog.exception(err)
                        resp = ServiceError("%s" % err)
                        return resp(environ)

        jlog.debug({"unknown side": path})
        resp = NotFound("Couldn't find the side you asked for!")
        return resp(environ, start_response)


def key_handling(key_dir):
    if isdir(key_dir):
        only_files = [f for f in listdir(key_dir) if isfile(join(key_dir, f))]
    else:
        os.makedirs(key_dir)
        only_files = []

    if not only_files:
        only_files = ['one.pem']
        for fil in only_files:
            key = RSA.generate(2048)
            f = open(join(key_dir, fil), 'w')
            f.write(key.exportKey('PEM').decode('utf8'))
            f.close()

    return {key_dir: only_files}


# def find_allowed_algorithms(metadata_file, ic):
#     mds = MetadataStore(ic.attribute_converters, ic,
#                         disable_ssl_certificate_validation=True)
#
#     mds.imp([{
#         "class": "saml2.mdstore.MetaDataFile",
#         "metadata": [(metadata_file,)]}])
#
#     md = mds.metadata[metadata_file]
#     ed = list(md.entity.values())[0]
#     res = {"digest_algorithms":[], "signing_algorithms":[]}
#
#     for elem in ed['extensions']['extension_elements']:
#         if elem['__class__'] == '{}&DigestMethod'.format(
# algsupport.NAMESPACE):
#             res['digest_algorithms'].append(elem['algorithm'])
#         elif elem['__class__'] == '{}&SigningMethod'.format(
#                 algsupport.NAMESPACE):
#             res['signing_algorithms'].append(elem['algorithm'])
#
#     return res


if __name__ == '__main__':
    import argparse
    from beaker.middleware import SessionMiddleware
    from Cryptodome.PublicKey import RSA

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument(
        '-k', dest='insecure', action='store_true',
        help='whether or not TLS certificate verification should be performed')
    parser.add_argument('-s', dest='tls', action='store_true',
                        help='Whether the server should handle SSL/TLS')
    parser.add_argument('-p', dest="profile", action='append',
                        help='The RP profile')
    parser.add_argument('-y', dest='yaml_flow', action='append',
                        help='Test descriptions in YAML format')
    parser.add_argument('-r', dest='rsa_key_dir', default='keys')
    parser.add_argument('-m', dest='path2port')
    parser.add_argument('-w', dest='cwd', help='change working directory')
    parser.add_argument(
        '-P', dest='port', help='Which port the test instance should listen at')
    parser.add_argument('-O', dest='op_profiles',
                        help='Possible OP (=test tool) profiles')
    parser.add_argument(
        '-c', dest="ca_certs",
        help="CA certs to use to verify HTTPS server certificates, " \
             "if HTTPS is used and no server CA certs are defined then " \
             "no cert verification will be done")
    parser.add_argument(
        '-x', dest='xport', help='ONLY for testing')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        # 'session.key': "{}.beaker.session.id".format(
        #     urlparse(_base).netloc.replace(":", "."))
    }

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    tool_args = config.TOOL_ARGS

    fdef = {'Flows': {}, 'Order': [], 'Desc': {}}
    for flow_def in args.yaml_flow:
        spec = parse_yaml_conf(flow_def, tool_args['cls_factories'],
                               tool_args['func_factory'])
        fdef['Flows'].update(spec['Flows'])
        fdef['Desc'].update(spec['Desc'])
        fdef['Order'].extend(spec['Order'])

    # Filter based on profile
    keep = []
    for key, val in fdef['Flows'].items():
        for p in args.profile:
            if p in val['profiles']:
                keep.append(key)

    for key in list(fdef['Flows'].keys()):
        if key not in keep:
            del fdef['Flows'][key]

    # Create necessary keys if I don't already have them
    keys = key_handling('keys')

    if args.insecure:
        disable_validation = True
    else:
        disable_validation = False

    if args.cwd:
        base_dir = args.cwd
    else:
        base_dir = os.getcwd()

    as_args, key_args = as_arg_setup(args, lookup=LOOKUP, config=config)

    _op_profiles = json.load(open(args.op_profiles))

    kwargs = {"base_url": as_args['name'], "test_specs": fdef,
              'flows': fdef['Flows'], 'order': fdef['Order'],
              "profile": args.profile, 'desc': fdef['Desc'],
              "msg_factory": tool_args['cls_factories'],
              "check_factory": tool_args['chk_factory'],
              'conf': config, "cache": {}, 'op_profiles': _op_profiles,
              "profile_handler": tool_args['profile_handler'], 'map_prof': None,
              'trace_cls': Trace, 'lookup': LOOKUP,
              'make_entity': make_entity, 'base_dir': base_dir,
              'signing_key': keys, 'provider_cls': tool_args['provider'],
              'as_args': as_args, 'response_cls': http_util.Response
              }

    if args.ca_certs:
        kwargs['ca_certs'] = args.ca_certs

    if args.path2port:
        kwargs['path'] = as_args['instance_path']

    _app = Application(base=as_args['name'], **kwargs)
    _app.endpoints = {
        '.well-known/openid-configuration': 'providerinfo_endpoint'
    }

    if args.xport:
        _port = int(args.xport)
    else:
        _port = int(as_args['instance_port'])

    # Initiate the web server
    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', _port),
        SessionMiddleware(_app.application, session_opts))

    if args.tls:
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(config.SERVER_CERT,
                                            config.SERVER_KEY,
                                            config.CERT_CHAIN)
        extra = "using SSL/TLS"
    else:
        extra = ""

    print('issuer: {}'.format(as_args['name']))
    txt = "RP test tool started {}.".format(extra)
    logger.info(txt)
    print(txt)

    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()

#!/usr/bin/env python

import importlib
from json import loads
import logging
import re
import sys
import requests
import traceback

from future.backports.urllib.parse import parse_qs
from future.backports.urllib.parse import urlencode
from future.backports.urllib.parse import urlparse

from mako.lookup import TemplateLookup

from aatest.check import WARNING
from aatest.events import EV_PROTOCOL_REQUEST
from aatest.events import NoSuchEvent
from aatest.summation import eval_state
from aatest.summation import get_errors
from aatest.verify import Verify

from oic.oauth2 import ErrorResponse

from oic.utils.http_util import NotFound
from oic.utils.http_util import SeeOther
from oic.utils.http_util import ServiceError
from oic.utils.http_util import Response
from oic.utils.http_util import BadRequest

from requests.packages import urllib3

from otest.rp.display import display
from otest.rp.endpoints import static
from otest.rp.endpoints import add_endpoints
from otest.rp.instance import Instances

urllib3.disable_warnings()

__author__ = 'roland'

logger = logging.getLogger("")
LOGFILE_NAME = 'tt.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

ROOT = './'

LOOKUP = TemplateLookup(directories=[ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')


def run_assertions(op_env, test_specs, conversation):
    try:
        req = conversation.events.last_item(EV_PROTOCOL_REQUEST)
    except NoSuchEvent:
        pass
    else:
        _ver = Verify(None, conversation)
        _ver.test_sequence(
            test_specs[op_env['test_id']][req.__class__.__name__]["assert"])


def construct_url(op, params, start_page):
    _params = params
    _params = _params.replace('<issuer>', op.baseurl)
    _args = dict([p.split('=') for p in _params.split('&')])
    return start_page + '?' + urlencode(_args)


def connection_error(environ, start_response, err):
    resp = Response("Connection error: {}".format(err))
    return resp(environ, start_response)


class WebApplication(object):
    def __init__(self, test_specs, conf_response, urls, lookup, op_env, 
                 instances):
        self.test_specs = test_specs
        self.conf_response = conf_response
        self.urls = urls
        self.lookup = lookup
        self.op_env = op_env
        self.instances = instances

    def application(self, environ, start_response):
        #  session = environ['beaker.session']

        path = environ.get('PATH_INFO', '').lstrip('/')

        if path == "robots.txt":
            resp = static("static/robots.txt")
            return resp(environ, start_response)
        elif path.startswith("static/"):
            resp = static(path)
            return resp(environ, start_response)
        elif path.startswith("favicon.ico"):
            resp = static('static/favicon.ico')
            return resp(environ, start_response)
        elif path == '':
            sid = self.instances.new_map()
            self.instances.remove_old()
            info = self.instances[sid]

            resp = Response(mako_template="test.mako",
                            template_lookup=self.lookup, headers=[])

            kwargs = {
                'events': '',
                'id': sid,
                'start_page': '',
                'params': '',
                'issuer': info['op'].baseurl,
                'http_result': '',
                'profiles': self.instances.profiles,
                'selected': info['selected']
            }
            return resp(environ, start_response, **kwargs)
        elif path == 'cp':
            qs = parse_qs(environ["QUERY_STRING"])
            resp = Response(mako_template="profile.mako",
                            template_lookup=self.lookup, headers=[])
            specs = loads(open('config_params.json').read())
            kwargs = {'specs': specs, 'id': qs['id'][0], 'selected': {}}
            return resp(environ, start_response, **kwargs)
        elif path == 'profile':
            qs = parse_qs(environ["QUERY_STRING"])
            sid = qs['_id_'][0]
            del qs['_id_']
            try:
                info = self.instances[sid]
            except KeyError:
                self.instances.new_map(sid)
                info = self.instances[sid]

            op = info['op']
            for key, val in qs.items():
                if val == ['True']:
                    qs[key] = True
                elif val == ['False']:
                    qs[key] = False

            if op.verify_capabilities(qs):
                op.capabilities = self.conf_response(**qs)
            else:
                # Shouldn't happen
                resp = ServiceError('Capabilities error')
                return resp(environ, start_response)

            info['selected'] = qs

            self.op_env['test_id'] = 'default'
            url = construct_url(op, info['params'], info['start_page'])
            try:
                rp_resp = requests.request('GET', url, verify=False)
            except Exception as err:
                return connection_error(environ, start_response, err)

            if rp_resp.status_code != 200:
                if rp_resp.text:
                    result = '{}:{}'.format(rp_resp.status_code, rp_resp.text)
                else:
                    result = '{}:{}'.format(rp_resp.status_code, rp_resp.reason)
            else:
                result = "200 OK"

            # How to recognize something went wrong ?
            resp = Response(mako_template="test.mako",
                            template_lookup=self.lookup, headers=[])
            kwargs = {
                'http_result': result,
                'events': display(info['conv'].events),
                'id': sid,
                'start_page': info['start_page'],
                'params': info['params'],
                'issuer': op.baseurl,
                'profiles': self.instances.profiles,
                'selected': info['selected']
            }
            return resp(environ, start_response, **kwargs)

        elif path == 'rp':
            qs = parse_qs(environ["QUERY_STRING"])

            # Modify the OP configuration
            # if 'setup' in testspecs[tid] and testspecs[tid]['setup']:
            #     for func, args in testspecs[tid]['setup'].items():
            #         func(_op, args)
            sid = qs['id'][0]
            try:
                info = self.instances[sid]
            except KeyError:
                self.instances.new_map(sid)
                info = self.instances[sid]

            _conv = info['conv']
            _op = info['op']

            _prof = qs['profile'][0]
            if _prof == 'custom':
                info['start_page'] = qs['start_page'][0]
                info['params'] = qs['params'][0]
                self.instances[sid] = info
                resp = SeeOther('/cp?id={}'.format(sid))
                return resp(environ, start_response)
            elif _prof != 'default':
                if _op.verify_capabilities(self.instances.profile[_prof]):
                    _op.capabilities = self.conf_response(
                        **self.instances.profile[_prof])
                else:
                    # Shouldn't happen
                    resp = ServiceError('Capabilities error')
                    return resp(environ, start_response)

            self.op_env['test_id'] = 'default'
            url = construct_url(_op, qs['params'][0], qs['start_page'][0])

            try:
                rp_resp = requests.request('GET', url, verify=False)
            except Exception as err:
                resp = ServiceError(err)
                return resp(environ, start_response)

            if rp_resp.status_code != 200:
                result = '{}:{}'.format(rp_resp.status_code, rp_resp.text)
            else:
                result = ""

            # How to recognize something went wrong ?
            resp = Response(mako_template="test.mako",
                            template_lookup=self.lookup, headers=[])
            kwargs = {
                'http_result': result,
                'events': display(_conv.events),
                'id': sid,
                'start_page': qs['start_page'][0],
                'params': qs['params'][0],
                'issuer': _op.baseurl,
                'profiles': self.instances.profiles,
                'selected': info['selected']
            }
            return resp(environ, start_response, **kwargs)

        if '/' in path:
            sid, _path = path.split('/', 1)
            try:
                info = self.instances[sid]
            except KeyError:
                sid = self.instances.new_map(sid)
                info = self.instances[sid]
                self.op_env['test_id'] = 'default'

            if _path == "result":
                resp = Response(mako_template="test.mako",
                                template_lookup=self.lookup, headers=[])
                _conv = info['conv']
                _op = info['op']
                kwargs = {
                    'http_result': '',
                    'events': display(_conv.events),
                    'id': sid,
                    'start_page': '',
                    'params': '',
                    'issuer': _op.baseurl,
                    'profiles': self.instances.profiles,
                    'selected': info['selected']
                }
                return resp(environ, start_response, **kwargs)
            elif _path == 'reset':
                self.instances.new_map(sid)
                resp = Response('Done')
                return resp(environ, start_response)

            environ["oic.op"] = info['op']
            conversation = info['conv']
            conversation.events.store('path', _path)

            for regex, callback in self.urls:
                match = re.search(regex, _path)
                if match is not None:
                    try:
                        environ['oic.url_args'] = match.groups()[0]
                    except IndexError:
                        environ['oic.url_args'] = _path

                    logger.info("callback: %s" % callback)
                    try:
                        resp = callback(environ, conversation.events)
                        # assertion checks
                        run_assertions(self.op_env, testspecs, conversation)
                        if eval_state(conversation.events) > WARNING:
                            err_desc = get_errors(conversation.events)
                            err_msg = ErrorResponse(error='invalid_request',
                                                    error_description=err_desc)
                            resp = BadRequest(err_msg.to_json())
                            return resp(environ, start_response)

                        return resp(environ, start_response)
                    except Exception as err:
                        print("%s" % err)
                        print(traceback.format_exception(*sys.exc_info()))
                        logger.exception("%s" % err)
                        resp = ServiceError("%s" % err)
                        return resp(environ, start_response)

        logger.debug("Unknown page: %s" % path)
        resp = NotFound("Couldn't find the page you asked for!")
        return resp(environ, start_response)


if __name__ == '__main__':
    import argparse
    from beaker.middleware import SessionMiddleware

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-t', dest='tests')
    parser.add_argument('-P', dest='profiles')
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)

    tool_args = config.TOOL_ARGS

    main_setup = tool_args['setup']

    as_args, op_arg, config = main_setup(args, LOOKUP, config)

    _base = "{base}:{port}/".format(base=config.baseurl, port=args.port)

    _instances = Instances(as_args, _base, op_arg['profiles'],
                           tool_args['provider'],
                           uri_schemes=op_arg['uri_schemes'])

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.key': "{}.beaker.session.id".format(
            urlparse(_base).netloc.replace(":", "."))
    }

    # target = config.TARGET.format(quote_plus(_base))
    # print(target)

    testspecs = tool_args['parse_conf'](
        args.tests, cls_factories=tool_args['cls_factories'],
        chk_factories=tool_args['chk_factories'],
        func_factories=tool_args['func_factories'])

    _urls = add_endpoints(tool_args['endpoints'], tool_args['urls'])

    _dir = "./"
    LOOKUP = TemplateLookup(directories=[_dir + 'templates', _dir + 'htdocs'],
                            module_directory=_dir + 'modules',
                            input_encoding='utf-8',
                            output_encoding='utf-8')

    WA = WebApplication(testspecs, tool_args['configuration_response'], _urls,
                        LOOKUP, {}, _instances)

    # Initiate the web server
    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', int(args.port)),
        SessionMiddleware(WA.application, session_opts))

    if args.tls:
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(config.SERVER_CERT,
                                            config.SERVER_KEY,
                                            config.CERT_CHAIN)
        extra = " using SSL/TLS"
    else:
        extra = ""

    txt = "RP test tool started. Listening on port:%s%s" % (args.port, extra)
    logger.info(txt)
    print(txt)

    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()

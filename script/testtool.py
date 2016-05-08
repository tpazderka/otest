#!/usr/bin/env python

import importlib
import os
import logging
import re
import sys
import requests
import traceback
from json import loads

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

from oic.utils.http_util import NotFound, get_post
from oic.utils.http_util import SeeOther
from oic.utils.http_util import ServiceError
from oic.utils.http_util import Response
from oic.utils.http_util import BadRequest

from requests.packages import urllib3

from otest.rp.endpoints import static, static_mime
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
    def __init__(self, test_specs, urls, lookup, op_env,
                 current_dir, **kwargs):
        self.test_specs = test_specs
        self.urls = urls
        self.lookup = lookup
        self.op_env = op_env
        self.current_dir = current_dir

    # def display_test_list(self):
    #     try:
    #         if self.sh.session_init():
    #             return self.inut.flow_list()
    #         else:
    #             try:
    #                 resp = Redirect("%s/opresult#%s" % (
    #                     self.inut.conf.BASE, self.sh["testid"][0]))
    #             except KeyError:
    #                 return self.inut.flow_list()
    #             else:
    #                 return resp(self.inut.environ, self.inut.start_response)
    #     except Exception as err:
    #         exception_trace("display_test_list", err)
    #         return self.inut.err_response("session_setup", err)

    def send_result(self, environ, start_response, rp_resp=None, **kwargs):
        if rp_resp:
            if rp_resp.status_code != 200:
                if rp_resp.text:
                    result = '{}:{}'.format(rp_resp.status_code, rp_resp.text)
                else:
                    result = '{}:{}'.format(rp_resp.status_code, rp_resp.reason)
            else:
                result = "200 OK"
        else:
            result = ''

        # How to recognize something went wrong ?
        resp = Response(mako_template="test.mako",
                        template_lookup=self.lookup, headers=[])

        return resp(environ, start_response, **kwargs)

    def init_sequence(self, environ, start_response, test_id, sid, info):
        _op = info['op']

        self.op_env['test_id'] = test_id
        url = construct_url(_op, info['params'], info['start_page'])

        try:
            rp_resp = requests.request('GET', url, verify=False)
        except Exception as err:
            resp = ServiceError(err)
            return resp(environ, start_response)

        return self.send_result(
            environ, start_response, id=sid,
            tests=info['tests'], base=_op.baseurl,
            test_info=info['test_info'], headlines=info['headlines'])

    def application(self, environ, start_response):
        #  session = environ['beaker.session']

        path = environ.get('PATH_INFO', '').lstrip('/')

        if path == "robots.txt" or path == "favicon.ico":
            return static_mime(os.path.join(self.current_dir, 'static', path),
                               environ, start_response)
        elif path.startswith("static/"):
            return static_mime(os.path.join(self.current_dir, path),
                               environ, start_response)
        elif path == '' or path == 'config':
            sid = self.instances.new_map()
            self.instances.remove_old()
            info = self.instances[sid]

            resp = Response(mako_template="config.mako",
                            template_lookup=self.lookup, headers=[])

            kwargs = {
                'id': sid,
                'start_page': '',
                'params': '',
                'issuer': info['op'].baseurl,
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

            return self.send_result(
                environ, start_response, resp=rp_resp, id=sid,
                tests=info['tests'], base=op.baseurl,
                test_info=info['test_info'], headlines=info['headlines'])
        elif path == 'flow':
            qs = parse_qs(get_post(environ))
            sid = qs['id'][0]
            try:
                info = self.instances[sid]
            except KeyError:
                self.instances.new_map(sid)
                info = self.instances[sid]

            _op = info['op']

            _prof = qs['profile'][0]
            for p in ['start_page', 'params', 'profile']:
                info[p] = qs[p][0]

            if _prof == 'custom':
                self.instances[sid] = info
                resp = SeeOther('/cp?id={}'.format(sid))
                return resp(environ, start_response)
            elif _prof != 'default':
                if _op.verify_capabilities(self.instances.profile_desc[_prof]):
                    _op.capabilities = self.conf_response(
                        **self.instances.profile_desc[_prof])
                else:
                    # Shouldn't happen
                    resp = ServiceError('Capabilities error')
                    return resp(environ, start_response)

            return self.send_result(
                environ, start_response, id=sid, base=_op.baseurl,
                tests=info['session_handler']['tests'],
                test_info=info['session_handler']['test_info'],
                headlines=info['headlines'])

        # elif path in self.kwargs['flows'].keys():  # Run flow
        #     resp = tester.run(path, **self.kwargs)
        #     if resp is True or resp is False:
        #         return tester.display_test_list()
        #     else:
        #         return resp(environ, start_response)
        # elif path == 'all':
        #     for test_id in sh['flow_names']:
        #         resp = tester.run(test_id, **self.kwargs)
        #         if resp is True or resp is False:
        #             continue
        #         elif resp:
        #             return resp(environ, start_response)
        #         else:
        #             resp = ServiceError('Unkown service error')
        #             return resp(environ, start_response)
        #     return tester.display_test_list()
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
                if _op.verify_capabilities(self.instances.profile_desc[_prof]):
                    _op.capabilities = self.conf_response(
                        **self.instances.profile_desc[_prof])
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

            return self.send_result(
                environ, start_response, id=sid,
                tests=info['tests'], base=_op.baseurl,
                test_info=info['test_info'], headlines=info['headlines'])

        if '/' in path:
            try:
                sid, test_id, _path = path.split('/', 2)
            except ValueError:
                sid, test_id = path.split('/', 1)
                _path = ''

            try:
                info = self.instances[sid]
            except KeyError:
                sid = self.instances.new_map(sid)
                info = self.instances[sid]

            if _path == '':
                return self.init_sequence(environ, start_response, test_id, sid,
                                          info)
            elif _path == "result":
                return self.send_result(
                    environ, start_response, id=sid,
                    tests=info['tests'], base=info['op'].baseurl,
                    test_info=info['test_info'], headlines=info['headlines'])
            elif _path == 'reset':
                self.instances.new_map(sid)
                resp = Response('Done')
                return resp(environ, start_response)
            else:
                _path = '/'.join([test_id, _path])

            environ["oic.op"] = info['op']
            conversation = info['conv']
            conversation.events.store('path', _path)

            for regex, callback in self.urls:
                match = re.search(regex, _path)
                if match is not None:
                    self.op_env['test_id'] = _path

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
    parser.add_argument('-t', dest='tests', action='append')
    parser.add_argument('-c', dest='cwd')
    parser.add_argument('-O', dest='op_profiles', action='append')
    parser.add_argument('-P', dest='profile')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)

    tool_args = config.TOOL_ARGS

    main_setup = tool_args['setup']

    as_args, op_arg, config = main_setup(args, LOOKUP, config)

    _base = "{base}:{port}/".format(base=config.baseurl, port=args.port)

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.key': "{}.beaker.session.id".format(
            urlparse(_base).netloc.replace(":", "."))
    }

    # target = config.TARGET.format(quote_plus(_base))
    # print(target)

    testspecs = {'Flows':{}, 'Order':[], 'Desc': {} }

    for t in args.tests:
        f = tool_args['parse_conf'](
            t, cls_factories=tool_args['cls_factories'],
            func_factory=tool_args['func_factory'])
        for p in ['Flows', 'Desc']:
            testspecs[p].update(f[p])
        testspecs['Order'].extend(f['Order'])

    _urls = add_endpoints(tool_args['endpoints'], tool_args['urls'])

    _dir = "./"
    LOOKUP = TemplateLookup(directories=[_dir + 'templates', _dir + 'htdocs'],
                            module_directory=_dir + 'modules',
                            input_encoding='utf-8',
                            output_encoding='utf-8')

    _instances = Instances(as_args, _base, op_arg['profiles'],
                           tool_args['provider'],
                           profile=args.profile,
                           uri_schemes=op_arg['uri_schemes'],
                           flows=testspecs['Flows'],
                           order=testspecs['Order'],
                           headlines=testspecs['Desc'])
    if args.cwd:
        current_dir = args.cwd
    else:
        current_dir = os.getcwd()

    WA = WebApplication(testspecs, tool_args['configuration_response'], _urls,
                        LOOKUP, {}, _instances, current_dir=current_dir)

    # Initiate the web server
    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', int(args.port)),
        SessionMiddleware(WA.application, session_opts))

    if _base.startswith("https"):
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

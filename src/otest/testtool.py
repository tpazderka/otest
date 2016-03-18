import importlib
from json import loads
import logging
import re
import sys
import requests
import time
import traceback

from future.backports.urllib.parse import parse_qs
from future.backports.urllib.parse import urlencode
from future.backports.urllib.parse import urlparse

from mako.lookup import TemplateLookup

from aatest.check import State, WARNING
from aatest.check import ERROR
from aatest.conversation import Conversation
from aatest.events import EV_REQUEST
from aatest.events import EV_CONDITION
from aatest.events import EV_HTTP_RESPONSE
from aatest.events import EV_PROTOCOL_REQUEST
from aatest.events import NoSuchEvent
from aatest.summation import eval_state
from aatest.summation import get_errors
from aatest.verify import Verify

from oic import rndstr
from oic.oauth2 import ErrorResponse

from oic.utils.http_util import NotFound
from oic.utils.http_util import SeeOther
from oic.utils.http_util import extract_from_request
from oic.utils.http_util import ServiceError
from oic.utils.http_util import Response
from oic.utils.http_util import BadRequest
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.webfinger import WebFinger

from requests.packages import urllib3
from otest.display import display

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
        _conv.events = as_args['event_db']
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


def run_assertions(op_env, testspecs, conversation):
    try:
        req = conversation.events.last_item(EV_PROTOCOL_REQUEST)
    except NoSuchEvent:
        pass
    else:
        _ver = Verify(None, conversation)
        _ver.test_sequence(
            testspecs[op_env['test_id']][req.__class__.__name__]["assert"])


def store_response(response, events):
    events.store(EV_HTTP_RESPONSE, response.info())


def wsgi_wrapper(environ, func, events, **kwargs):
    kwargs = extract_from_request(environ, kwargs)
    if kwargs['request']:
        events.store(EV_REQUEST, kwargs['request'])
    args = func(**kwargs)

    try:
        resp, state = args
        store_response(resp, events)
        return resp
    except TypeError:
        resp = args
        store_response(resp, events)
        return resp
    except Exception as err:
        logger.error("%s" % err)
        raise


# noinspection PyUnresolvedReferences
def static(path):
    logger.info("[static]sending: %s" % (path,))

    try:
        resp = Response(open(path).read())
        if path.endswith(".ico"):
            resp.add_header(('Content-Type', "image/x-icon"))
        elif path.endswith(".html"):
            resp.add_header(('Content-Type', 'text/html'))
        elif path.endswith(".json"):
            resp.add_header(('Content-Type', 'application/json'))
        elif path.endswith(".txt"):
            resp.add_header(('Content-Type', 'text/plain'))
        elif path.endswith(".css"):
            resp.add_header(('Content-Type', 'text/css'))
        else:
            resp.add_header(('Content-Type', "text/xml"))
        return resp
    except IOError:
        return NotFound(path)


def css(environ, events):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except (OSError, IOError):
        resp = NotFound(environ["PATH_INFO"])

    return resp


def token(environ, events):
    _op = environ["oic.op"]

    return wsgi_wrapper(environ, _op.token_endpoint, events)


def authorization(environ, events):
    _op = environ["oic.op"]

    return wsgi_wrapper(environ, _op.authorization_endpoint,
                        events)


def userinfo(environ, events):
    _op = environ["oic.op"]

    return wsgi_wrapper(environ, _op.userinfo_endpoint,
                        events)


def clientinfo(environ, events):
    _op = environ["oic.op"]

    return wsgi_wrapper(environ, _op.client_info_endpoint,
                        events)


def revocation(environ, events):
    _op = environ["oic.op"]

    return wsgi_wrapper(environ, _op.revocation_endpoint,
                        events)


def introspection(environ, events):
    _op = environ["oic.op"]

    return wsgi_wrapper(environ, _op.introspection_endpoint, events)


# noinspection PyUnusedLocal
def op_info(environ, events):
    _op = environ["oic.op"]
    logger.info("op_info")
    return wsgi_wrapper(environ, _op.providerinfo_endpoint,
                        events)


# noinspection PyUnusedLocal
def registration(environ, events):
    _op = environ["oic.op"]

    if environ["REQUEST_METHOD"] == "POST":
        return wsgi_wrapper(environ, _op.registration_endpoint,
                            events)
    elif environ["REQUEST_METHOD"] == "GET":
        return wsgi_wrapper(environ, _op.read_registration,
                            events)
    else:
        return ServiceError("Method not supported")


def webfinger(environ, events):
    query = parse_qs(environ["QUERY_STRING"])
    _op = environ["oic.op"]

    try:
        if query["rel"] != [OIC_ISSUER]:
            events.store(
                EV_CONDITION,
                State('webfinger_parameters', ERROR,
                      message='parameter rel wrong value: {}'.format(
                          query['rel'])))
            return BadRequest('Parameter value error')
        else:
            resource = query["resource"][0]
    except KeyError as err:
        events.store(EV_CONDITION,
                       State('webfinger_parameters', ERROR,
                             message='parameter {} missing'.format(err)))
        resp = BadRequest("Missing parameter in request")
    else:
        wf = WebFinger()
        resp = Response(wf.response(subject=resource, base=_op.baseurl))
    return resp


def add_endpoints(extra, URLS):
    for endp in extra:
        URLS.append(("^%s" % endp.etype, endp.func))

    return URLS


def construct_url(op, params, start_page):
    _params = params
    _params = _params.replace('<issuer>', op.baseurl)
    args = dict([p.split('=') for p in _params.split('&')])
    return start_page + '?' + urlencode(args)


def application(environ, start_response):
    session = environ['beaker.session']
    path = environ.get('PATH_INFO', '').lstrip('/')

    testspecs = session._params['test_specs']
    conf_response = session._params['conf_response']
    urls = session._params['urls']

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
        sid = INST.new_map()
        INST.remove_old()
        info = INST[sid]

        resp = Response(mako_template="test.mako",
                        template_lookup=session._params['lookup'],
                        headers=[])

        kwargs = {
            'events': '',
            'id': sid,
            'start_page': '',
            'params': '',
            'issuer': info['op'].baseurl,
            'http_result': '',
            'profiles': INST.profiles,
            'selected': info['selected']
        }
        return resp(environ, start_response, **kwargs)
    elif path == 'cp':
        qs = parse_qs(environ["QUERY_STRING"])
        resp = Response(mako_template="profile.mako",
                        template_lookup=session._params['lookup'],
                        headers=[])
        specs = loads(open('config_params.json').read())
        kwargs = {'specs': specs, 'id': qs['id'][0], 'selected': {}}
        return resp(environ, start_response, **kwargs)
    elif path == 'profile':
        qs = parse_qs(environ["QUERY_STRING"])
        sid = qs['_id_'][0]
        del qs['_id_']
        try:
            info = INST[sid]
        except KeyError:
            INST.new_map(sid)
            info = INST[sid]

        op = info['op']
        for key, val in qs.items():
            if val == ['True']:
                qs[key] = True
            elif val == ['False']:
                qs[key] = False

        if op.verify_capabilities(qs):
            op.capabilities = conf_response(**qs)
        else:
            # Shouldn't happen
            resp = ServiceError('Capabilities error')
            return resp(environ, start_response)

        info['selected'] = qs

        session._params['op_env']['test_id'] = 'default'
        url = construct_url(op, info['params'], info['start_page'])
        try:
            rp_resp = requests.request('GET', url, verify=False)
        except Exception as err:
            resp = ServiceError(err)
            return resp(environ, start_response)

        if rp_resp.status_code != 200:
            if rp_resp.text:
                result = '{}:{}'.format(rp_resp.status_code, rp_resp.text)
            else:
                result = '{}:{}'.format(rp_resp.status_code, rp_resp.reason)
        else:
            result = "200 OK"

        # How to recognize something went wrong ?
        resp = Response(mako_template="test.mako",
                        template_lookup=session._params['lookup'],
                        headers=[])
        kwargs = {
            'http_result': result,
            'events': display(info['conv'].events),
            'id': sid,
            'start_page': info['start_page'],
            'params': info['params'],
            'issuer': op.baseurl,
            'profiles': INST.profiles,
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
            info = INST[sid]
        except KeyError:
            INST.new_map(sid)
            info = INST[sid]

        _conv = info['conv']
        _op = info['op']

        _prof = qs['profile'][0]
        if _prof == 'custom':
            info['start_page'] = qs['start_page'][0]
            info['params'] = qs['params'][0]
            INST[sid] = info
            resp = SeeOther('/cp?id={}'.format(sid))
            return resp(environ, start_response)
        elif _prof != 'default':
            if _op.verify_capabilities(INST.profile[_prof]):
                _op.capabilities = conf_response(
                    **INST.profile[_prof])
            else:
                # Shouldn't happen
                resp = ServiceError('Capabilities error')
                return resp(environ, start_response)

        session._params['op_env']['test_id'] = 'default'
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
                        template_lookup=session._params['lookup'],
                        headers=[])
        kwargs = {
            'http_result': result,
            'events': display(_conv.events),
            'id': sid,
            'start_page': qs['start_page'][0],
            'params': qs['params'][0],
            'issuer': _op.baseurl,
            'profiles': INST.profiles,
            'selected': info['selected']
        }
        return resp(environ, start_response, **kwargs)

    if '/' in path:
        sid, _path = path.split('/', 1)
        info = INST[sid]
        environ["oic.op"] = info['op']
        conversation = info['conv']
        conversation.events.store('path', _path)

        for regex, callback in urls:
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
                    run_assertions(session._params['op_env'], testspecs,
                                   conversation)
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
    parser.add_argument(dest="config")
    args = parser.parse_args()

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)

    tool_args = config.TOOL_ARGS

    main_setup = tool_args['setup']

    as_args, op_arg, config = main_setup(args, LOOKUP, config)

    _base = "{base}:{port}/".format(base=config.baseurl, port=args.port)

    INST = Instances(as_args, _base, op_arg['profiles'], tool_args['provider'],
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

    # Initiate the web server
    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', int(args.port)),
        SessionMiddleware(application, session_opts,
                          test_specs=testspecs, op_env={}, lookup=LOOKUP,
                          conf_response=tool_args['configuration_response'],
                          urls=_urls))

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

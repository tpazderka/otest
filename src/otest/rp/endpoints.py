import logging
import mimetypes
import os

from otest.check import State
from otest.check import ERROR
from otest.events import EV_CONDITION
from otest.events import EV_HTTP_INFO
from otest.events import EV_REQUEST

from future.backports.urllib.parse import parse_qs

from oic.utils.http_util import BadRequest
from oic.utils.http_util import extract_from_request
from oic.utils.http_util import NotFound
from oic.utils.http_util import Response
from oic.utils.http_util import ServiceError

from oic.utils.webfinger import OIC_ISSUER
from oic.utils.webfinger import WebFinger

__author__ = 'roland'

logger = logging.getLogger(__name__)


def store_response(response, events):
    events.store(EV_HTTP_INFO, response.info())


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
def static_mime(path, environ, start_response):
    logger.info("[static]sending: %s" % (path,))

    # Set content-type based on filename extension
    ext = ""
    i = path.rfind('.')
    if i != -1:
        ext = path[i:].lower()
    content_type = mimetypes.types_map.get(ext, None)

    try:
        if not content_type.startswith('image/'):
            data = open(path, 'r').read()
        else:
            data = open(path, 'rb').read()
        resp = Response(data, content=content_type)
        return resp(environ, start_response)
    except IOError:
        _dir = os.getcwd()
        resp = NotFound("{} not in {}".format(path, _dir))
    except Exception as err:
        resp = NotFound('{}'.format(err))

    return resp(environ, start_response)


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

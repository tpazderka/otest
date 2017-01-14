import logging
import os

from oic.utils.http_util import BadRequest
from oic.utils.http_util import SeeOther

from otest.events import EV_HTTP_ARGS
from otest.result import safe_url

__author__ = 'roland'

logger = logging.getLogger(__name__)


class WebApplication(object):
    def __init__(self, sessionhandler, webio, webtester, check, webenv,
                 pick_grp, path=''):
        self.sessionhandler = sessionhandler
        self.webio = webio
        self.webtester = webtester
        self.check = check
        self.webenv = webenv
        self.pick_grp = pick_grp
        self.path = path

    def application(self, environ, start_response):
        logger.info("Connection from: %s" % environ["REMOTE_ADDR"])
        session = environ['beaker.session']

        path = environ.get('PATH_INFO', '').lstrip('/')
        logger.info("path: %s" % path)

        try:
            sh = session['session_info']
        except KeyError:
            sh = self.sessionhandler(**self.webenv)
            sh.session_init()
            session['session_info'] = sh

        info = self.webio(session=sh, **self.webenv)
        info.environ = environ
        info.start_response = start_response
        tester = self.webtester(info, sh, **self.webenv)
        tester.check_factory = self.check.factory

        if path == "robots.txt":
            return info.static("static/robots.txt")
        elif path == "favicon.ico":
            return info.static("static/favicon.ico")
        elif path.startswith("static/"):
            return info.static(path)
        elif path.startswith("jwks/"):
            return info.static(path)
        elif path.startswith("export/"):
            return info.static(path)

        if self.path and path.startswith(self.path):
            _path = path[len(self.path)+1:]
        else:
            _path = path

        if _path == "":  # list
            return tester.display_test_list()

        if _path == "logs":
            return info.display_log("log", issuer="", profile="", testid="")
        elif _path.startswith("log"):
            if _path == "log" or _path == "log/":
                try:
                    _iss = self.webenv['client_info']["provider_info"]["issuer"]
                except KeyError:
                    _iss = self.webenv['tool_conf']['issuer']

                parts = [safe_url(_iss)]
            else:
                parts = []
                while _path != "log":
                    head, tail = os.path.split(_path)
                    # tail = tail.replace(":", "%3A")
                    # if tail.endswith("%2F"):
                    #     tail = tail[:-3]
                    parts.insert(0, tail)
                    _path = head

            return info.display_log("log", *parts)
        elif _path.startswith("tar"):
            _path = _path.replace(":", "%3A")
            return info.static(_path)

        if _path == "reset":
            sh.reset_session()
            return info.flow_list()
        elif _path == "pedit":
            try:
                return info.profile_edit()
            except Exception as err:
                return info.err_response("pedit", err)
        elif _path == "profile":
            return tester.set_profile(environ)
        elif _path.startswith("test_info"):
            p = _path.split("/")
            try:
                return info.test_info(p[1])
            except KeyError:
                return info.not_found()
        elif _path == "continue":
            resp = tester.cont(environ, self.webenv)
            session['session_info'] = info.session
            if resp:
                return resp
            else:
                resp = SeeOther(
                    "{}display#{}".format(self.webenv['base_url'],
                                           self.pick_grp(sh['conv'].test_id)))
                return resp(environ, start_response)
        elif _path == 'display':
            return info.flow_list()
        elif _path == "opresult":
            resp = SeeOther(
                "{}display#{}".format(self.webenv['base_url'],
                                     self.pick_grp(sh['conv'].test_id)))
            return resp(environ, start_response)
        # expected _path format: /<testid>[/<endpoint>]
        elif _path in sh["tests"]:
            resp = tester.run(_path, **self.webenv)
            session['session_info'] = info.session

            if resp is False or resp is True:
                pass
            elif isinstance(resp, list):
                return resp

            try:
                #  return info.flow_list()
                resp = SeeOther(
                    "{}display#{}".format(
                        self.webenv['client_info']['base_url'],
                        self.pick_grp(sh['conv'].test_id)))
                return resp(environ, start_response)
            except Exception as err:
                logger.error(err)
                raise
        elif _path in ["authz_cb", "authz_post"]:
            if _path == "authz_cb":
                _conv = sh["conv"]
                try:
                    response_mode = _conv.req.req_args["response_mode"]
                except KeyError:
                    response_mode = ""

                # Check if fragment encoded
                if response_mode == "form_post":
                    pass
                else:
                    try:
                        response_type = _conv.req.req_args["response_type"]
                    except KeyError:
                        response_type = [""]

                    if response_type == [""]:  # expect anything
                        if environ["QUERY_STRING"]:
                            pass
                        else:
                            return info.opresult_fragment()
                    elif response_type != ["code"]:
                        # but what if it's all returned as a query anyway ?
                        try:
                            qs = environ["QUERY_STRING"]
                        except KeyError:
                            pass
                        else:
                            _conv.events.store(EV_HTTP_ARGS, qs)
                            _conv.query_component = qs

                        return info.opresult_fragment()

            try:
                resp = tester.async_response(self.webenv["conf"])
            except Exception as err:
                return info.err_response("authz_cb", err)
            else:
                if resp is False or resp is True:
                    pass
                elif not isinstance(resp, int):
                    return resp

                try:
                    # return info.flow_list()
                    resp = SeeOther(
                        "{}display#{}".format(
                            self.webenv['client_info']['base_url'],
                            self.pick_grp(sh['conv'].test_id)))
                    return resp(environ, start_response)
                except Exception as err:
                    logger.error(err)
                    raise
        else:
            resp = BadRequest()
            return resp(environ, start_response)

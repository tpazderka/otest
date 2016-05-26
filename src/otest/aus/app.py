import logging
import os

from future.backports.urllib.parse import quote_plus

from oic.utils.http_util import BadRequest
from oic.utils.http_util import SeeOther

__author__ = 'roland'

logger = logging.getLogger(__name__)


class WebApplication(object):
    def __init__(self, sessionhandler, webio, webtester, check, webenv,
                 pick_grp):
        self.sessionhandler = sessionhandler
        self.webio = webio
        self.webtester = webtester
        self.check = check
        self.webenv = webenv
        self.pick_grp = pick_grp

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

        inut = self.webio(session=sh, **self.webenv)
        inut.environ = environ
        inut.start_response = start_response

        tester = self.webtester(inut, sh, **self.webenv)
        tester.check_factory = self.check.factory

        if path == "robots.txt":
            return inut.static("static/robots.txt")
        elif path == "favicon.ico":
            return inut.static("static/favicon.ico")
        elif path.startswith("static/"):
            return inut.static(path)
        elif path.startswith("export/"):
            return inut.static(path)

        if path == "":  # list
            return tester.display_test_list()

        if path == "logs":
            return inut.display_log("log", issuer="", profile="", testid="")
        elif path.startswith("log"):
            if path == "log" or path == "log/":
                _cc = inut.conf.CLIENT
                try:
                    _iss = _cc["srv_discovery_url"]
                except KeyError:
                    _iss = _cc["provider_info"]["issuer"]
                parts = [quote_plus(_iss)]
            else:
                parts = []
                while path != "log":
                    head, tail = os.path.split(path)
                    # tail = tail.replace(":", "%3A")
                    # if tail.endswith("%2F"):
                    #     tail = tail[:-3]
                    parts.insert(0, tail)
                    path = head

            return inut.display_log("log", *parts)
        elif path.startswith("tar"):
            path = path.replace(":", "%3A")
            return inut.static(path)

        if path == "reset":
            sh.reset_session()
            return inut.flow_list()
        elif path == "pedit":
            try:
                return inut.profile_edit()
            except Exception as err:
                return inut.err_response("pedit", err)
        elif path == "profile":
            return tester.set_profile(environ)
        elif path.startswith("test_info"):
            p = path.split("/")
            try:
                return inut.test_info(p[1])
            except KeyError:
                return inut.not_found()
        elif path == "continue":
            resp = tester.cont(environ, self.webenv)
            session['session_info'] = inut.session
            if resp:
                return resp
            else:
                resp = SeeOther(
                    "/display#{}".format(self.pick_grp(sh['conv'].test_id)))
                return resp(environ, start_response)
        elif path == 'display':
            return inut.flow_list()
        elif path == "opresult":
            resp = SeeOther(
                "/display#{}".format(self.pick_grp(sh['conv'].test_id)))
            return resp(environ, start_response)
        # expected path format: /<testid>[/<endpoint>]
        elif path in sh["flow_names"]:
            resp = tester.run(path, **self.webenv)
            session['session_info'] = inut.session

            if resp is False or resp is True:
                pass
            elif resp:
                return resp

            try:
                #return inut.flow_list()
                resp = SeeOther(
                    "/display#{}".format(
                        self.pick_grp(path)))
                return resp(environ, start_response)
            except Exception as err:
                logger.error(err)
                raise
        elif path in ["authz_cb", "authz_post"]:
            if path == "authz_cb":
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
                            return inut.opresult_fragment()
                    elif response_type != ["code"]:
                        # but what if it's all returned as a query anyway ?
                        try:
                            qs = environ["QUERY_STRING"]
                        except KeyError:
                            pass
                        else:
                            _conv.trace.response("QUERY_STRING:%s" % qs)
                            _conv.query_component = qs

                        return inut.opresult_fragment()

            try:
                resp = tester.async_response(self.webenv["conf"])
            except Exception as err:
                return inut.err_response("authz_cb", err)
            else:
                if resp is False or resp is True:
                    pass
                elif resp:
                    return resp

                try:
                    #return inut.flow_list()
                    resp = SeeOther(
                        "/display#{}".format(
                            self.pick_grp(sh['conv'].test_id)))
                    return resp(environ, start_response)
                except Exception as err:
                    logger.error(err)
                    raise
        else:
            resp = BadRequest()
            return resp(environ, start_response)
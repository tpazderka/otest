import logging
import os

# from urllib.parse import unquote
from future.backports.urllib.parse import unquote

from oic.utils.http_util import NotFound
from oic.utils.http_util import Response

from otest.check import ERROR
from otest.check import OK
from otest.check import WARNING
from otest.check import INCOMPLETE
from otest.io import IO
from otest.log import with_or_without_slash
from otest.summation import represent_result
from otest.summation import store_test_state
from otest.utils import get_test_info

__author__ = 'roland'

logger = logging.getLogger(__name__)

TEST_RESULTS = {OK: "OK", ERROR: "ERROR", WARNING: "WARNING",
                INCOMPLETE: "INCOMPLETE"}


class WebIO(IO):
    def __init__(self, conf, flows, desc, profile_handler, profile, lookup,
                 cache=None, environ=None, start_response=None, session=None,
                 base_url='', **kwargs):
        IO.__init__(self, flows, profile, desc, profile_handler, cache,
                    session=session, **kwargs)

        self.conf = conf
        self.lookup = lookup
        self.environ = environ
        self.start_response = start_response
        self.base_url = base_url

    def flow_list(self):
        try:
            resp = Response(mako_template="flowlist.mako",
                            template_lookup=self.lookup,
                            headers=[])
        except Exception as err:
            logger.error(err)
            raise

        argv = {
            "flows": self.session["tests"],
            "profile": self.session["profile"],
            "test_info": list(self.session["test_info"].keys()),
            "base": self.base_url,
            "headlines": self.desc,
            "testresults": TEST_RESULTS,
        }

        return resp(self.environ, self.start_response, **argv)

    def profile_edit(self):
        resp = Response(mako_template="profile.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {"profile": self.session["profile"]}
        return resp(self.environ, self.start_response, **argv)

    def test_info(self, testid):
        resp = Response(mako_template="testinfo.mako",
                        template_lookup=self.lookup,
                        headers=[])

        info = get_test_info(self.session, testid)

        argv = {
            "profile": info["profile_info"],
            "events": info['events'],
            "result": represent_result(info['events']).replace("\n", "<br>\n"),
            'base': self.base_url
        }

        return resp(self.environ, self.start_response, **argv)

    def not_found(self):
        """Called if no URL matches."""
        resp = NotFound()
        return resp(self.environ, self.start_response)

    def static(self, path):
        logger.info("[static]sending: %s" % (path,))

        try:
            text = open(path, 'rb').read()
            logger.debug('Read {} bytes'.format(len(text)))
            if path.endswith(".ico"):
                self.start_response('200 OK', [('Content-Type',
                                                "image/x-icon")])
            elif path.endswith(".html"):
                self.start_response('200 OK', [('Content-Type', 'text/html')])
            elif path.endswith(".json"):
                self.start_response('200 OK', [('Content-Type',
                                                'application/json')])
            elif path.endswith(".jwt"):
                self.start_response('200 OK', [('Content-Type',
                                                'application/jwt')])
            elif path.endswith(".txt"):
                self.start_response('200 OK', [('Content-Type', 'text/plain')])
            elif path.endswith(".css"):
                self.start_response('200 OK', [('Content-Type', 'text/css')])
            else:
                self.start_response('200 OK', [('Content-Type', "text/plain")])
            return [text]
        except IOError:
            resp = NotFound()
            return resp(self.environ, self.start_response)

    def _display(self, root, issuer, profile):
        item = []
        logger.debug('curdir:{}'.format(os.curdir))
        if profile:
            path = os.path.join(root, issuer, profile).replace(":", "%3A")
            argv = {"issuer": unquote(issuer), "profile": profile}

            path = with_or_without_slash(path)
            if path is None:
                resp = Response("No saved logs")
                return resp(self.environ, self.start_response)

            for _name in os.listdir(path):
                if _name.startswith("."):
                    continue
                fn = os.path.join(path, _name)
                if os.path.isfile(fn):
                    item.append((unquote(_name), os.path.join(profile, _name)))
        else:
            if issuer:
                argv = {'issuer': unquote(issuer), 'profile': ''}
                path = os.path.join(root, issuer).replace(":", "%3A")
            else:
                argv = {'issuer': '', 'profile': ''}
                path = root

            path = with_or_without_slash(path)
            if path is None:
                resp = Response("No saved logs")
                return resp(self.environ, self.start_response)

            for _name in os.listdir(path):
                if _name.startswith("."):
                    continue
                fn = os.path.join(path, _name)
                if os.path.isdir(fn):
                    item.append((unquote(_name), os.path.join(path, _name)))

        resp = Response(mako_template="logs.mako",
                        template_lookup=self.lookup,
                        headers=[])

        item.sort()
        argv["logs"] = item
        argv["base"] = self.base_url
        return resp(self.environ, self.start_response, **argv)

    def display_log(self, root, issuer="", profile="", testid=""):
        """

        :param root:
        :param issuer:
        :param profile:
        :param testid:
        :return:
        """
        logger.info(
            "display_log root: '{root}' issuer: '{iss}', profile: '{prof}' "
            "testid: '{tid}'".format(
                root=root, iss=issuer, prof=profile, tid=testid))
        if testid:
            path = os.path.join(root, issuer, profile, testid).replace(":",
                                                                       "%3A")
            return self.static(path)
        else:
            if issuer:
                return self._display(root, issuer, profile)
            else:
                resp = Response("No saved logs")
                return resp(self.environ, self.start_response)

    def err_response(self, where, err):
        self._err_response(where, err)
        return self.flow_list()

    def sorry_response(self, homepage, err):
        resp = Response(mako_template="sorry.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {
            "htmlpage": homepage,
            "error": str(err),
            'base': self.base_url
        }
        return resp(self.environ, self.start_response, **argv)

    def opresult(self, conv):
        store_test_state(conv.events, self.session)
        return self.flow_list()

    def opresult_fragment(self):
        resp = Response(mako_template="opresult_repost.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {'base': self.base_url}
        return resp(self.environ, self.start_response, **argv)

    def respond(self, resp):
        if isinstance(resp, Response):
            return resp(self.environ, self.start_response)
        else:
            return resp

import logging
import os

# from urllib.parse import unquote
from future.backports.urllib.parse import unquote

from oic.utils.http_util import NotFound
from oic.utils.http_util import Response

from otest.aus.preproc.flow_list import display_profile, op_choice, legends
from otest.aus.preproc.logs import display_log
from otest.aus.preproc.profile import profile_form
from otest.check import ERROR
from otest.check import OK
from otest.check import WARNING
from otest.check import INCOMPLETE
from otest.handling import InfoHandling
from otest.utils import with_or_without_slash
from otest.summation import represent_result

__author__ = 'roland'

logger = logging.getLogger(__name__)

TEST_RESULTS = {OK: "OK", ERROR: "ERROR", WARNING: "WARNING",
                INCOMPLETE: "INCOMPLETE"}


class WebIh(InfoHandling):
    def __init__(self, conf=None, flows=None, profile_handler=None, profile='',
                 cache=None, environ=None, start_response=None,
                 session=None, base_url='', pre_html=None, **kwargs):
        InfoHandling.__init__(self, flows=flows, profile=profile,
                              profile_handler=profile_handler,
                              cache=cache, session=session, **kwargs)

        self.conf = conf
        self.environ = environ
        self.start_response = start_response
        self.base_url = base_url
        self.pre_html = pre_html

    def flow_list(self):
        _msg = self.pre_html['flow_list.html'].format(
            display_profile=display_profile(self.session["profile"]),
            op_choice=op_choice(
                self.base_url,
                self.flows.display_info(self.session['tests'])),
            legends=legends())
        return _msg

    def profile_edit(self):
        _msg = self.pre_html["profile.html"].format(
            profile_form=profile_form(self.session["profile"]),
            base=self.base_url)
        return _msg

    def test_info(self, testid):
        info = self.flows.test_info[testid]
        _msg = self.pre_html['testinfo.html'].format(
            profile=info["profile_info"],
            events=info['events'],
            result=represent_result(info['events']).replace("\n", "<br>\n"),
            base=self.base_url
        )
        return _msg

    def not_found(self):
        """Called if no URL matches."""
        resp = NotFound()
        return resp(self.environ, self.start_response)

    def _display(self, root, issuer, profile):
        item = []
        logger.debug('curdir:{}'.format(os.getcwd()))
        if profile:
            path = os.path.join(root, issuer, profile).replace(":", "%3A")
            argv = {"issuer": unquote(issuer), "profile": profile}

            path = with_or_without_slash(path)
            if path is None:
                return "No saved logs"

            for _name in os.listdir(path):
                if _name.startswith("."):
                    continue
                fn = os.path.join(path, _name)
                if os.path.isfile(fn):
                    item.append((unquote(_name), fn))
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

        item.sort()
        _msg = self.pre_html['logs.html'].format(
            display_log=display_log(logs = item, base = self.base_url, **argv))
        return _msg

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
        self._store_error(where, err)
        return self.flow_list()

    @staticmethod
    def reset_link(url):
        return "<a href='%sreset'>link</a>" % url

    def sorry_response(self, homepage, err):
        _msg = self.pre_html['sorry.html'].format(
            error=str(err),
            link=self.reset_link(self.base_url)
        )
        return _msg

    # def opresult(self, conv):
    #     return self.flow_list()
    #
    def opresult_fragment(self):
        _msg = self.pre_html['opresult_repost.html']
        return _msg

    def respond(self, resp):
        if isinstance(resp, Response):
            return resp(self.environ, self.start_response)
        else:
            return resp

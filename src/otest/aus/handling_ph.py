import logging
import os

# from urllib.parse import unquote
import cherrypy
from future.backports.urllib.parse import unquote

from otest.aus.preproc.flow_list import display_profile
from otest.aus.preproc.flow_list import legends
from otest.aus.preproc.flow_list import op_choice
from otest.aus.preproc.logs import display_log
from otest.aus.preproc.profile import profile_form
from otest.aus.preproc.testinfo import do_assertions
from otest.aus.preproc.testinfo import profile_output
from otest.aus.preproc.testinfo import trace_output

from otest.check import ERROR
from otest.check import OK
from otest.check import WARNING
from otest.check import INCOMPLETE
from otest.handling import InfoHandling
from otest.result import safe_url
from otest.utils import with_or_without_slash
from otest.summation import represent_result

__author__ = 'roland'

logger = logging.getLogger(__name__)

TEST_RESULTS = {OK: "OK", ERROR: "ERROR", WARNING: "WARNING",
                INCOMPLETE: "INCOMPLETE"}


class WebIh(InfoHandling):
    def __init__(self, conf=None, flow_state=None, profile_handler=None,
                 cache=None, session=None, base_url='',
                 pre_html=None, **kwargs):
        InfoHandling.__init__(self, flow_state=flow_state,
                              profile_handler=profile_handler,
                              cache=cache, session=session, **kwargs)

        self.conf = conf
        self.base_url = base_url
        self.pre_html = pre_html

    def flow_list(self):
        try:
            _tests = self.session['tests']
        except KeyError:
            _tests = self.flow_state.matches_profile(self.session.profile)
            self.session['tests'] = _tests

        _msg = self.pre_html['flow_list.html'].format(
            display_profile=display_profile(self.session.profile),
            op_choice=op_choice(
                self.base_url,
                self.flow_state.display_info(_tests)),
            legends=legends(),
            version=self.session.tool_version
        )
        return _msg

    def profile_edit(self):
        _msg = self.pre_html["profile.html"].format(
            profile_form=profile_form(self.session.profile),
            version=self.session.tool_version,
            base=self.base_url)
        return _msg

    def test_info(self, testid):
        try:
            info = self.flow_state.test_info[testid]
        except KeyError:
            _sess = self.session

            _l = ["You have not run this test during this test session.<br>"]
            _su = safe_url(_sess.iss)
            path0 = "log/{}/{}/{}/{}".format(_su, _sess.tag, _sess.profile,
                                             testid)
            if _su.endswith('2F'):
                path1 = "log/{}/{}/{}/{}".format(_su[:-2], _sess.tag,
                                                 _sess.profile, testid)
            else:
                path1 = "log/{}2F/{}/{}/{}".format(_su, _sess.tag,
                                                   _sess.profile, testid)

            for _path in [path0, path1]:
                if os.path.isfile(_path):
                    _l.extend([
                        "If you want to see a previous run you can look here ",
                        '<a href="/{}">link</a><br>'.format(_path)])

            return self.pre_html['sorry.html'].format(
                error='\n'.join(_l),
                link='<a href="{}">link</a>'.format(self.base_url)
            )
        else:
            _events = info['events']
            _msg = self.pre_html['testinfo.html'].format(
                profile_output=profile_output(
                    info["profile_info"],
                    version=self.session.tool_version),
                trace_output=trace_output(_events),
                result=represent_result(_events).replace("\n", "<br>\n"),
                assertions=do_assertions(_events),
                base=self.base_url,
                version=self.session.tool_version
            )
            return _msg

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
                return b'No saved logs'

            for _name in os.listdir(path):
                if _name.startswith("."):
                    continue
                fn = os.path.join(path, _name)
                if os.path.isdir(fn):
                    item.append((unquote(_name), os.path.join(path, _name)))

        item.sort()
        _msg = self.pre_html['logs.html'].format(
            display_log=display_log(logs=item, base=self.base_url, **argv),
            version=self.session.tool_version
        )
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
            raise cherrypy.HTTPRedirect(path)
        else:
            if issuer:
                return self._display(root, issuer, profile)
            else:
                return b'No saved logs'

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

    def opresult_fragment(self):
        _msg = self.pre_html['opresult_repost.html']
        return _msg

    def respond(self, resp):
        return resp

import logging

from oic.utils.http_util import Response, NotFound

from otest.summation import represent_result
from otest.check import ERROR
from otest.check import OK
from otest.check import WARNING
from otest.check import INCOMPLETE
from otest.io import IO

__author__ = 'roland'

logger = logging.getLogger(__name__)

TEST_RESULTS = {OK: "OK", ERROR: "ERROR", WARNING: "WARNING",
                INCOMPLETE: "INCOMPLETE"}

def get_test_info(session, test_id):
    return session["test_info"][test_id]


class WebIO(IO):
    def __init__(self, conf, flows, desc, profile_handler, profile, lookup,
                 cache=None, environ=None, start_response=None, session=None,
                 **kwargs):
        IO.__init__(self, flows, profile, desc, profile_handler, cache,
                    session=session, **kwargs)

        self.conf = conf
        self.lookup = lookup
        self.environ = environ
        self.start_response = start_response

        try:
            self.base_url = kwargs['base_url']
        except KeyError:
            try:
                self.base_url = kwargs['base']
            except KeyError:
                self.base_url = conf.BASE

    def flow_list(self, **kwargs):
        resp = Response(mako_template="flowlist.mako",
                        template_lookup=self.lookup,
                        headers=[])

        argv = {
            "tests": self.session["tests"],
            "profile": self.session["profile"],
            "test_info": list(self.session["test_info"].keys()),
            "base": self.base_url,
            "headlines": self.desc,
            "testresults": TEST_RESULTS
        }

        argv.update(kwargs)
        return resp(self.environ, self.start_response, **argv)

    def test_info(self, testid):
        resp = Response(mako_template="testinfo.mako",
                        template_lookup=self.lookup,
                        headers=[])

        _conv = self.session["conv"]
        info = get_test_info(self.session, testid)

        argv = {
            "profile": info["profile_info"],
            "trace": info["trace"],
            "events": info["events"].timeline(),
            "result": represent_result(_conv.events).replace("\n", "<br>\n"),
            "base": self.base_url,
        }

        return resp(self.environ, self.start_response, **argv)

    def not_found(self):
        """Called if no URL matches."""
        resp = NotFound()
        return resp(self.environ, self.start_response)

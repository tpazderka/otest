import logging

from otest import exception_trace, Break
from otest.check import ERROR, State
from otest.check import WARNING
from otest.events import EV_CONDITION
from otest.result import Result
from otest.result import SIGN
from otest.summation import eval_state
from otest.summation import represent_result

__author__ = 'roland'

logger = logging.getLogger(__name__)


class InfoHandling(object):
    def __init__(self, flow_state, desc=None, profile_handler=None,
                 cache=None, session=None, **kwargs):
        self.flow_state = flow_state
        self.cache = cache
        self.profile_handler = profile_handler
        self.desc = desc
        self.session = session

    @property
    def profile(self):
        if self.session:
            return self.session.profile
        else:
            return ''

    def represent_result(self, events):
        return represent_result(events)

    def _store_error(self, where, err):
        if err:
            exception_trace(where, err, logger)

    def err_response(self, where, err):
        self._store_error(where, err)

    def get_err_type(self, test_id):
        errt = WARNING
        try:
            if self.session.profile.split('.')[0] in self.flow_state[
                    test_id]['MTI']:
                errt = ERROR
        except KeyError:
            pass
        return errt

    def log_fault(self, session, err, where, err_type=0):
        if err_type == 0:
            err_type = self.get_err_type(session)

        if "conv" in session:
            if err:
                session["conv"].events.store(EV_CONDITION,
                                             State("Fault", status=ERROR,
                                                   name=err_type,
                                                   message="{}".format(err)))
            else:
                session["conv"].events.store(
                    EV_CONDITION, State(
                        "Fault", status=ERROR,
                        name=err_type,
                        message="Error in %s" % where))


class ClIh(InfoHandling):
    def __init__(self, flows=None, profile='', desc='', profile_handler=None,
                 cache=None, session=None, **kwargs):
        InfoHandling.__init__(self, flows, profile=profile, desc=desc,
                              profile_handler=profile_handler,
                              cache=cache, session=session, **kwargs)

    def flow_list(self):
        pass

    def result(self):
        _state = eval_state(self.session["conv"].events)
        print(("{} {}".format(SIGN[_state], self.session["node"].name)))

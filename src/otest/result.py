import logging
import os

from future.backports.urllib.parse import quote

from otest.check import ERROR
from otest.check import OK
from otest.check import WARNING
from otest.check import INCOMPLETE
from otest.summation import condition
from otest.summation import represent_result
from otest.summation import trace_output
from otest.summation import eval_state
from otest.time_util import in_a_while

SIGN = {OK: "+", WARNING: "!", ERROR: "-", INCOMPLETE: "?"}
TEST_RESULTS = {OK: "OK", ERROR: "ERROR", WARNING: "WARNING",
                INCOMPLETE: "INCOMPLETE"}

logger = logging.getLogger(__name__)


def get_issuer(conv):
    try:
        return conv.info['issuer']  # dynamically acquired using WebFinger
    except KeyError:
        try:
            # From provider info discovery, dynamic or static
            return conv.entity.provider_info['issuer']
        except KeyError:
            try:
                # Initial configuration
                return conv.tool_config['issuer']
            except KeyError:
                return 'unknown'


def safe_path(eid, *args):
    s = quote(eid)
    s = s.replace('/', '%2F')

    path = 'log/{}'.format(s)
    for arg in args[:-1]:
        path = '{}/{}'.format(path, arg)

    if not os.path.isdir(path):
        os.makedirs(path)

    return '{}/{}'.format(path, args[-1])


class Result(object):
    def __init__(self, session, profile_handler):
        self.profile_handler = profile_handler
        self.session = session

    def result(self):
        _state = eval_state(self.session["conv"].events)
        print("{} {}".format(SIGN[_state], self.session["node"].name))

    def print_result(self, events):
        return represent_result(events)

    def _profile_info(self, test_id):
        if self.profile_handler:
            ph = self.profile_handler(self.session)
            try:
                return ph.get_profile_info(test_id)
            except Exception as err:
                raise
        return {}

    def write_info(self, test_id, file_name=None):
        if file_name is None:
            _iss = get_issuer(self.session['conv'])
            if _iss.endswith('/'+test_id):
                _iss = _iss[:-(len(test_id)+1)]

            file_name = safe_path(_iss, self.session['profile'],
                                  self.session['testid'])

        if 'conv' not in self.session:
            return
        else:
            _conv = self.session["conv"]

        sline = 60 * "="

        _pi = self._profile_info(test_id)

        if _pi:
            _keys = list(_pi.keys())
            _keys.sort()
            output = ["%s: %s" % (k, _pi[k]) for k in _keys]
        else:
            output = ['Test ID: {}'.format(_conv.test_id),
                      "Timestamp: {}".format(in_a_while())]

        output.extend(["", sline, ""])
        output.extend(trace_output(_conv.events))
        output.extend(["", sline, ""])
        output.extend(condition(_conv.events))
        output.extend(["", sline, ""])
        # and lastly the result
        output.append(
            "RESULT: {}".format(self.print_result(_conv.events)))
        output.append("")

        txt = "\n".join(output)

        f = self._open_file(file_name, 'w')
        f.write(txt)
        f.close()

    def _test_info(self, profile_info=None):
        _info = {
            "descr": self.session["node"].desc,
            "events": self.session["conv"].events,
            "index": self.session["index"],
            # "seqlen": len(self.session["seq_info"]["sequence"]),
            "test_output": self.session["conv"].events.get('condition'),
            "trace": self.session["conv"].trace,
        }

        try:
            _info["node"] = self.session["seq_info"]["node"]
        except KeyError:
            pass

        if profile_info:
            _info["profile_info"] = profile_info
        else:
            _info['profile_info'] = self._profile_info(self.session["testid"])

        return _info

    def store_test_info(self, profile_info=None):
        self.session["test_info"][self.session["testid"]] = self._test_info(
            profile_info)

    def _open_file(self, file_name, mode='w'):
        try:
            fp = open(file_name, mode)
        except IOError:
            try:
                os.makedirs(os.path.dirname(file_name))
            except OSError:
                pass

            try:
                fp = open(file_name, mode)
            except Exception as err:
                logger.error(
                    "Couldn't dump to log file {} reason: {}").format(
                    file_name, err)
                raise
        return fp

    def dump_log(self):
        file_name = safe_path(self.session['conv'].conf.ISSUER,
                              self.session['profile'], self.session['testid'])

        _info = self._test_info()

        fp = self._open_file(file_name)

        fp.write("{0}".format(_info))
        fp.write("\n\n")
        fp.close()

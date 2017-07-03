import logging
import os

from future.backports.urllib.parse import quote
from oic.oauth2.provider import Provider

from otest.check import CRITICAL
from otest.check import ERROR
from otest.check import NOT_APPLICABLE
from otest.check import OK
from otest.check import WARNING
from otest.check import INCOMPLETE
from otest.summation import condition
from otest.summation import represent_result
from otest.summation import result_code
from otest.summation import trace_output
from otest.time_util import in_a_while

SIGN = {OK: "+", WARNING: "!", ERROR: "-", INCOMPLETE: "?",
        NOT_APPLICABLE: 'N/A', CRITICAL: "X"}

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
        except (KeyError, AttributeError):
            try:
                # Initial configuration
                return conv.tool_config['issuer']
            except KeyError:
                return 'unknown'


def safe_url(url):
    if url.startswith('https://'):
        url = 's_' + url[8:]
    elif url.startswith('http://'):
        url = url[7:]

    s = quote(url)
    s = s.replace('/', '%2F')
    s = s.replace('%', '')
    s = s.replace('//', '/')
    return s


def safe_path(eid, ext='', *args):
    """

    :param eid: Entity (Issuer) ID, a URL
    :param ext: Log file extension
    :param args: Additional arguments
    :return: A URL and reverse proxy safe path
    """
    s = safe_url(eid)
    path = 'log/{}'.format(s)
    for arg in args[:-1]:
        path = '{}/{}'.format(path, arg)

    if not os.path.isdir(path):
        os.makedirs(path)

    fname = '{}/{}'.format(path, args[-1])
    if ext:
        fname += '.{}'.format(ext)
    return fname


class Result(object):
    """
    Reads and writes test result information to files on disc.
    Keeps a cache for quick access.
    """

    def __init__(self, session, profile_handler):
        self.profile_handler = profile_handler
        self.session = session
        self.cache = {}
        self.logfile_extension = 'txt'

    def print_result(self, events):
        return represent_result(events)

    def op_based(self, test_id, tag=''):
        _sess = self.session
        _iss = _sess.iss
        if _iss.endswith('/' + test_id):
            _iss = _iss[:-(len(test_id) + 1)]
        if not tag:
            tag = _sess.tag
        return safe_path(_iss, self.logfile_extension, tag, _sess.profile,
                         test_id)

    def rp_based(self, test_id, tag=''):
        _sess = self.session
        return safe_path(_sess['test_conf']['start_page'],
                         self.logfile_extension, _sess.profile, test_id)

    def write_info(self, tinfo, test_id='', file_name=None, tag=''):
        if not test_id:
            test_id = tinfo['test_id']

        if file_name is None:
            if isinstance(self.session['conv'].entity, Provider):
                file_name = self.rp_based(test_id, tag)
            else:
                file_name = self.op_based(test_id, tag)

        if 'conv' not in self.session:
            return
        else:
            _conv = self.session["conv"]

        sline = 60 * "="

        _pi = tinfo['profile_info']

        output = ["Test tool version: {}".format(self.session.tool_version)]
        if _pi:
            _keys = list(_pi.keys())
            _keys.sort()
            output.extend(["%s: %s" % (k, _pi[k]) for k in _keys])
        else:
            output.extend(['Test ID: {}'.format(_conv.test_id),
                           "Timestamp: {}".format(in_a_while())])

        _events = tinfo["events"]
        output.extend(["", sline, ""])
        output.extend(trace_output(_events))
        output.extend(["", sline, ""])
        output.extend(condition(_events))
        output.extend(["", sline, ""])
        # and lastly the result
        output.append("RESULT: {}".format(self.print_result(_events)))
        output.append("")

        txt = "\n".join(output)

        f = self._open_file(file_name, 'w')
        f.write(txt)
        f.close()

        self.cache[test_id] = {'result': result_code(_events),
                               'file_name': file_name}

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

    def test_status(self, tid):
        return self.cache[tid]

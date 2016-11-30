import copy
import inspect
import json
import logging
import time
import sys

from oic.utils.http_util import Response

from otest.events import EV_EXCEPTION, EV_FUNCTION
from otest.events import EV_PROTOCOL_RESPONSE
from otest.events import EV_RESPONSE
from otest.verify import Verify

from otest.events import EV_OP_ARGS

logger = logging.getLogger(__name__)


def print_result(resp):
    try:
        cl_name = resp.__class__.__name__
    except AttributeError:
        cl_name = ""
        txt = resp
    else:
        txt = json.dumps(resp.to_dict(), sort_keys=True, indent=2,
                         separators=(',', ': '))

    logger.info("{}: {}".format(cl_name, txt))


def request_with_client_http_session(instance, method, url, **kwargs):
    """Use the clients http session to make http request.
    Note: client.http_request function requires the parameters in reverse
    order (compared to the requests library): (method, url) vs (url, method)
    so we can't bind the instance method directly.
    """
    return instance.conv.entity.http_request(url, method)


class Operation(object):
    _tests = {"pre": [], "post": []}
    message_cls = None

    def __init__(self, conv, inut, sh, test_id='', conf=None, funcs=None,
                 check_factory=None, cache=None, profile='', tool_conf=None,
                 **kwargs):
        self.conv = conv
        self.inut = inut
        self.sh = sh
        self.funcs = funcs or {}
        self.test_id = test_id
        self.conf = conf
        self.check_factory = check_factory
        self.cache = cache
        self.profile = profile
        self.tool_conf = tool_conf
        self.req_args = {}
        self.op_args = {}
        self.expect_exception = None
        self.expect_error = None
        self.sequence = []
        self.skip = False
        self.fail = False
        self.allowed_status_codes = [200]
        # detach
        self.tests = copy.deepcopy(self._tests)
        try:
            self.internal = kwargs['internal']
        except KeyError:
            self.internal = True

    def run(self, *args, **kwargs):
        return None

    def post_tests(self):
        if self.tests["post"]:
            cls_name = self.__class__.__name__
            _ver = Verify(self.check_factory, self.conv, cls_name=cls_name)
            _ver.test_sequence(self.tests["post"])

    def __call__(self, *args, **kwargs):
        if self.skip:
            return
        else:
            cls_name = self.__class__.__name__
            if self.tests["pre"] or self.tests["post"]:
                _ver = Verify(self.check_factory, self.conv, cls_name=cls_name)
            else:
                _ver = None

            if self.tests["pre"]:
                _ver.test_sequence(self.tests["pre"])

            self.conv.events.store(
                EV_FUNCTION, {'name': cls_name, 'args': args, 'kwargs': kwargs})

            res = self.run(*args, **kwargs)

            if res:
                return res

    def _setup(self):
        if self.skip:  # Don't bother
            return

        for op, arg in list(self.funcs.items()):
            op(self, arg)

        self.conv.events.store(EV_OP_ARGS, self.op_args)

    def apply_profile(self, profile_map):
        try:
            kwargs = profile_map[self.__class__][self.profile[0]]
        except KeyError:
            return
        else:
            for op, arg in kwargs.items():
                op(self, arg)

    def op_setup(self):
        pass

    def setup(self, profile_map=None):
        """
        Order between setup methods are significant

        :param profile_map:
        :return:
        """
        if profile_map:
            self.apply_profile(profile_map)
        self.op_setup()
        self._setup()

    def catch_exception(self, func, **kwargs):
        res = None
        try:
            self.conv.events.store(EV_FUNCTION,
                                 {'name': func.__name__, 'kwargs': kwargs})
            res = func(**kwargs)
        except Exception as err:
            self.conv.events.store(EV_EXCEPTION, err)
            if not self.expect_exception:
                raise
            elif not err.__class__.__name__ == self.expect_exception:
                raise
            else:
                self.conv.events.store(EV_EXCEPTION, err, )
        else:
            if self.expect_exception:
                raise Exception(
                    "Expected exception '{}'.".format(self.expect_exception))
            if res:
                self.conv.trace.reply(res)
                if isinstance(res, self.message_cls):
                    self.conv.events.store(EV_PROTOCOL_RESPONSE, res)
                else:
                    self.conv.events.store(EV_RESPONSE, res)
        return res

    def handle_response(self, *args):
        raise NotImplemented

    def handle_request(self, *args):
        raise NotImplemented


class Notice(Operation):
    template = ""

    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.message = ""

    def args(self):
        return {}

    def __call__(self, *args, **kwargs):
        resp = Response(mako_template=self.template,
                        template_lookup=self.inut.lookup,
                        headers=[])
        return resp(self.inut.environ, self.inut.start_response,
                    **self.args())


class Note(Notice):
    template = "note.mako"

    def op_setup(self):
        self.message = self.conv.flow["note"]

    def args(self):
        return {
            "url": "%scontinue?path=%s&index=%d" % (
                self.conv.entity.base_url, self.test_id, self.sh["index"]),
            "back": self.conv.entity.base_url,
            "note": self.message,
            "base": self.conv.entity.base_url
        }


class TimeDelay(Operation):
    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.delay = 30

    def __call__(self, *args, **kwargs):
        time.sleep(self.delay)
        return None


class ProtocolMessage(object):
    def __init__(self, conv, req_args, binding, msg_param=None):
        self.conv = conv
        self.entity = conv.entity
        self.req_args = req_args
        self.binding = binding
        self.msg_param = msg_param or {}
        self.response_args = {}
        self.op_args = {}

    def construct_message(self, *args):
        raise NotImplementedError()

    def handle_response(self, result, *args):
        raise NotImplementedError()


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj

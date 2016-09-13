import logging
#from urllib.parse import parse_qs
from future.backports.urllib.parse import parse_qs


from oic.utils.http_util import Redirect
from oic.utils.http_util import Response
from oic.utils.http_util import get_post

from otest import Break
from otest import CRYPTSUPPORT
from otest import Done
from otest import exception_trace
from otest import tool
from otest import Trace
from otest.check import ERROR
from otest.check import OK
from otest.check import State
from otest.conversation import Conversation
from otest.events import EV_CONDITION
from otest.events import EV_REDIRECT_URL
from otest.io import eval_state
from otest.result import Result
from otest.result import safe_path
from otest.summation import store_test_state
from otest.verify import Verify

__author__ = 'roland'

logger = logging.getLogger(__name__)


def get_redirect_uris(cinfo):
    try:
        return cinfo["client"]["redirect_uris"]
    except KeyError:
        return cinfo["registered"]["redirect_uris"]


class Tester(tool.Tester):
    def __init__(self, io, sh, profiles, profile, flows=None,
                 check_factory=None, msg_factory=None, cache=None,
                 map_prof=None, **kwargs):
        tool.Tester.__init__(self, io, sh, profile=profile, flows=flows,
                             msg_factory=msg_factory, cache=cache, **kwargs)
        self.profiles = profiles
        self.check_factory = check_factory
        self.map_prof = map_prof
        self.conv = None

    def match_profile(self, test_id):
        _spec = self.flows[test_id]
        return self.map_prof(self.profile.split("."),
                             _spec["profile"].split("."))

    def fname(self, test_id):
        try:
            return safe_path(
                self.conv.entity.provider_info['issuer'],
                self.profile, test_id)
        except KeyError:
            return safe_path('dummy', self.profile, test_id)

    def run_flow(self, test_id, index=0, profiles=None, conf=None):
        logger.info("<=<=<=<=< %s >=>=>=>=>" % test_id)
        self.sh["node"].complete = False
        self.conv.test_id = test_id
        self.conv.conf = conf

        if index >= len(self.conv.sequence):
            return None

        res = Result(self.sh, self.kwargs['profile_handler'])

        _oper = None
        for item in self.conv.sequence[index:]:
            self.sh["index"] = index
            if isinstance(item, tuple):
                cls, funcs = item
            else:
                cls = item
                funcs = {}

            logger.info("<--<-- {} --- {} -->-->".format(index, cls))
            self.conv.trace.info("<--<-- {} --- {} -->-->".format(index, cls))
            try:
                _oper = cls(conv=self.conv, inut=self.inut, sh=self.sh,
                            profile=self.profile, test_id=test_id, conf=conf,
                            funcs=funcs, check_factory=self.check_factory,
                            cache=self.cache)
                self.conv.operation = _oper
                _oper.setup(self.profiles.PROFILEMAP)
                resp = _oper()
            except Break:
                break
            except Exception as err:
                self.conv.events.store(
                    EV_CONDITION,
                    State(test_id=test_id, status=ERROR, message=err,
                          context=cls.__name__))
                exception_trace(cls.__name__, err, logger)
                self.sh["index"] = index
                res.store_test_info()
                store_test_state(self.sh, self.conv.events)
                return self.inut.err_response("run_sequence", err)
            else:
                rsp = self.handle_response(resp, index)
                if rsp:
                    res.store_test_info()
                    store_test_state(self.sh, self.conv.events)
                    return self.inut.respond(rsp)

            index += 1

        if isinstance(_oper, Done):
            try:
                if self.conv.flow["assert"]:
                    _ver = Verify(self.check_factory, self.conv)
                    _ver.test_sequence(self.conv.flow["assert"])
            except KeyError:
                pass
            except Exception as err:
                raise

            self.conv.events.store(EV_CONDITION, State('Done', status=OK))
            store_test_state(self.sh, self.conv.events)
            res.store_test_info()
            res.print_info(test_id, self.fname(test_id))
        else:
            store_test_state(self.sh, self.conv.events)
            res.store_test_info()

        if eval_state(self.conv.events) == OK:
            return True
        else:
            return False


class ClTester(Tester):
    pass


class WebTester(Tester):
    def display_test_list(self):
        try:
            if self.sh.session_init():
                return self.inut.flow_list()
            else:
                try:
                    resp = Redirect("%sopresult#%s" % (
                        self.kwargs['base_url'], self.sh["testid"][0]))
                except KeyError:
                    return self.inut.flow_list()
                else:
                    return resp(self.inut.environ, self.inut.start_response)
        except Exception as err:
            exception_trace("display_test_list", err)
            return self.inut.err_response("session_setup", err)

    def set_profile(self, environ):
        info = parse_qs(get_post(environ))
        try:
            cp = self.sh["profile"].split(".")
            cp[0] = info["rtype"][0]

            crsu = []
            for name, cs in list(CRYPTSUPPORT.items()):
                try:
                    if info[name] == ["on"]:
                        crsu.append(cs)
                except KeyError:
                    pass

            if len(cp) == 3:
                if len(crsu) == 3:
                    pass
                else:
                    cp.append("".join(crsu))
            else:  # len >= 4
                cp[3] = "".join(crsu)

            try:
                if info["extra"] == ['on']:
                    if len(cp) == 3:
                        cp.extend(["", "+"])
                    elif len(cp) == 4:
                        cp.append("+")
                    elif len(cp) == 5:
                        cp[4] = "+"
                else:
                    if len(cp) == 5:
                        cp = cp[:-1]
            except KeyError:
                if len(cp) == 5:
                    cp = cp[:-1]

            # reset all test flows
            self.sh.reset_session(profile=".".join(cp))
            return self.inut.flow_list()
        except Exception as err:
            return self.inut.err_response("profile", err)

    def setup(self, test_id, cinfo, **kw_args):
        redirs = get_redirect_uris(cinfo)

        _flow = self.flows[test_id]
        _cli = self.make_entity(**kw_args)
        self.conv = Conversation(_flow, _cli, kw_args["msg_factory"],
                                 trace_cls=Trace, callback_uris=redirs)
        # _cli.conv = self.conv
        _cli.event_store = self.conv.events
        # since webfinger is not used
        self.conv.info['issuer'] = kw_args['conf'].INFO["srv_discovery_url"]
        self.sh.session_setup(path=test_id)
        self.sh["conv"] = self.conv
        self.conv.sequence = self.sh["sequence"]
        return True

    def handle_response(self, resp, index, oper=None):
        if resp:
            self.sh["index"] = index
            if isinstance(resp, Response):
                if self.conv.events.last_event_type() != EV_REDIRECT_URL:
                    self.conv.events.store(EV_REDIRECT_URL, resp.message)
                return resp(self.inut.environ, self.inut.start_response)
            else:
                return resp
        else:
            return None

    def store_state(self, test_id, complete):
        sess = self.sh
        sess['node'].complete = complete
        sess['node'].state = eval_state(sess['conv'].events)
        res = Result(sess, self.kwargs['profile_handler'])
        res.print_info(test_id, self.fname(test_id))

    def cont(self, environ, ENV):
        query = parse_qs(environ["QUERY_STRING"])
        path = query["path"][0]
        index = int(query["index"][0])

        try:
            index = self.sh["index"]
        except KeyError:  # Cookie delete broke session
            self.setup(path, **ENV)
        except Exception as err:
            return self.inut.err_response("session_setup", err)
        else:
            self.conv = self.sh["conv"]

        index += 1

        res = Result(self.sh, self.kwargs['profile_handler'])
        res.store_test_info()
        store_test_state(self.sh, self.conv.events)

        try:
            return self.run_flow(path, conf=ENV["conf"], index=index)
        except Exception as err:
            exception_trace("", err, logger)
            res = Result(self.sh, self.kwargs['profile_handler'])
            res.print_info(path)
            return self.inut.err_response("run", err)

    def async_response(self, conf):
        index = self.sh["index"]
        item = self.sh["sequence"][index]
        self.conv = self.sh["conv"]

        if isinstance(item, tuple):
            cls, funcs = item
        else:
            cls = item

        logger.info("<--<-- {} --- {}".format(index, cls))
        resp = self.conv.operation.parse_response(self.sh["testid"],
                                                  self.inut,
                                                  self.message_factory)
        if resp:
            return resp

        index += 1

        return self.run_flow(self.sh["testid"], index=index)

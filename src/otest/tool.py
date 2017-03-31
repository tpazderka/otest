import logging

from otest import ConditionError
from otest import Done
from otest import exception_trace
from otest.check import CRITICAL
from otest.check import ERROR
from otest.check import OK
from otest.check import State
from otest.conversation import Conversation
from otest.events import EV_CONDITION
from otest.events import EV_FAULT
from otest.result import Result
from otest.verify import Verify

__author__ = 'roland'

logger = logging.getLogger(__name__)


def get_redirect_uris(cinfo):
    """
    Used before there is a Conversation instance
    :param cinfo: Client Configuration Information
    :return: list of redirect_uris
    """
    try:
        res = cinfo["registration_info"]["redirect_uris"]
    except KeyError:
        res = cinfo["registration_response"]["redirect_uris"]

    if isinstance(res, ("".__class__, u"".__class__)):
        return [res]
    else:
        return res


class ConfigurationError(Exception):
    pass


class Tester(object):
    def __init__(self, inut, sh, profile='', flows=None, check_factory=None,
                 msg_factory=None, cache=None, make_entity=None, map_prof=None,
                 com_handler=None, response_cls=None,
                 client_factory=None, **kwargs):
        self.inut = inut
        self.sh = sh
        self.conv = None
        self.profile = profile
        self.flows = flows
        self.message_factory = msg_factory
        self.check_factory = check_factory
        self.client_factory = client_factory
        self.cache = cache
        self.kwargs = kwargs
        self.make_entity = make_entity
        self.map_prof = map_prof
        self.com_handler = com_handler
        self.cjar = {}
        self.response_cls = response_cls

    def match_profile(self, test_id):
        _spec = self.flows[test_id]
        return self.map_prof(self.profile.split("."),
                             _spec["profile"].split("."))

    def setup(self, test_id, **kw_args):
        redirs = get_redirect_uris(kw_args['client_info'])

        _flow = self.flows[test_id]
        _cli, _cli_info = self.client_factory.make_client(
            **kw_args['client_info'])
        self.conv = Conversation(_flow, _cli, kw_args["msg_factory"],
                                 callback_uris=redirs)
        self.conv.entity_config = _cli_info
        self.conv.tool_config = kw_args['tool_conf']
        _cli.conv = self.conv
        _cli.events = self.conv.events
        self.sh.session_setup(path=test_id)
        self.sh["conv"] = self.conv
        self.conv.sequence = self.sh["sequence"]
        return True

    def run(self, test_id, **kw_args):
        if not self.setup(test_id, **kw_args):
            raise ConfigurationError()

        # noinspection PyTypeChecker
        try:
            return self.run_flow(test_id, conf=kw_args['conf'])
        except Exception as err:
            exception_trace("", err, logger)
            self.store_result()
            return self.inut.err_response("run", err)

    def handle_response(self, resp, index, oper=None):
        return None

    def fname(self, test_id):
        raise NotImplemented()

    def get_response(self, resp):
        try:
            return resp.response
        except AttributeError:
            return resp.text

    def store_result(self, res=None):
        tinfo = self.flows.store_test_info(self)
        if res is None:
            res = Result(self.sh, self.kwargs['profile_handler'])
        res.write_info(tinfo)
        return tinfo

    def run_flow(self, test_id, index=0, profiles=None, **kwargs):
        logger.info("<=<=<=<=< %s >=>=>=>=>" % test_id)
        _ss = self.sh
        _ss.test_flows.complete[test_id] = False

        self.conv.test_id = test_id
        res = Result(self.sh, self.kwargs['profile_handler'])

        if index >= len(self.conv.sequence):
            return CRITICAL

        _oper = None
        for item in self.conv.sequence[index:]:
            if isinstance(item, tuple):
                cls, funcs = item
            else:
                cls = item
                funcs = {}

            logger.info("<--<-- {} --- {} -->-->".format(index, cls))
            self.conv.events.store('operation', cls, sender='run_flow')
            try:
                _oper = cls(conv=self.conv, inut=self.inut, sh=self.sh,
                            profile=self.profile, test_id=test_id,
                            funcs=funcs, check_factory=self.check_factory,
                            cache=self.cache)
                # self.conv.operation = _oper
                if profiles:
                    profile_map = profiles.PROFILEMAP
                else:
                    profile_map = None
                _oper.setup(profile_map)
                resp = _oper()
            except ConditionError:
                self.store_result(res)
                return ERROR
            except Exception as err:
                exception_trace('run_flow', err)
                self.conv.events.store(EV_FAULT, err)
                #self.sh["index"] = index
                self.store_result(res)
                return CRITICAL
            else:
                if isinstance(resp, self.response_cls):
                    return resp

                if resp:
                    if self.com_handler:
                        resp = self.com_handler(resp)

                    resp = _oper.handle_response(self.get_response(resp))

                    if resp:
                        return self.inut.respond(resp)

            # should be done as late as possible, so all processing has been
            # done
            try:
                _oper.post_tests()
            except ConditionError:
                tinfo = self.store_result(res)
                return tinfo['state']

            index += 1

        _ss['index'] = self.conv.index = index

        try:
            if self.conv.flow["assert"]:
                _ver = Verify(self.check_factory, self.conv)
                _ver.test_sequence(self.conv.flow["assert"])
        except KeyError:
            pass
        except Exception as err:
            logger.error(err)
            raise

        if isinstance(_oper, Done):
            self.conv.events.store(EV_CONDITION, State('Done', OK),
                                   sender='run_flow')

        tinfo = self.store_result(res)

        return tinfo['state']

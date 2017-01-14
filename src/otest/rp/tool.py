import logging
import os

from future.backports.urllib.parse import parse_qs
from oic.oauth2 import AuthorizationErrorResponse
from oic.oauth2 import AuthorizationRequest
from oic.oauth2 import PyoidcError
from oic.utils.http_util import Redirect
from oic.utils.http_util import Response

from otest import ConditionError
from otest import ConfigurationError
from otest import Done
from otest import exception_trace
from otest import tool
from otest.check import OK
from otest.check import State
from otest.conversation import Conversation
from otest.events import EV_CONDITION
from otest.events import EV_OPERATION
from otest.events import EV_PROTOCOL_REQUEST
from otest.events import EV_REQUEST
from otest.events import EV_RESPONSE
from otest.result import Result
from otest.result import safe_path
from otest.verify import Verify

logger = logging.getLogger(__name__)


class WebTester(tool.Tester):
    def __init__(self, *args, **kwargs):
        tool.Tester.__init__(self, *args, **kwargs)
        try:
            self.base_url = self.conv.entity.base_url
        except AttributeError:
            self.base_url = self.kwargs['base']
        self.provider_cls = self.kwargs['provider_cls']
        self.selected = {}

    def fname(self, test_id):
        _pname = '_'.join(self.profile)
        try:
            return safe_path(self.conv.entity_id, _pname, test_id)
        except (AttributeError, KeyError):
            return safe_path('dummy', _pname, test_id)

    def match_profile(self, test_id, **kwargs):
        _spec = self.flows[test_id]
        # There must be an intersection between the two profile lists.
        if self.sh.profile in _spec["usage"]["return_type"]:
            return True
        else:
            return False

    def setup(self, test_id, **kw_args):
        if not self.match_profile(test_id):
            return False

        self.sh.session_setup(path=test_id)
        _flow = self.flows[test_id]
        try:
            _cap = kw_args['op_profiles'][self.sh['test_conf']['profile']]
        except KeyError:
            _cap = None
        _ent = self.provider_cls(capabilities=_cap, **kw_args['as_args'])
        _ent.baseurl = os.path.join(_ent.baseurl, kw_args['sid'])
        _ent.jwks_uri = os.path.join(_ent.baseurl,
                                     kw_args['as_args']['jwks_name'])
        _ent.name = _ent.baseurl
        self.conv = Conversation(_flow, _ent,
                                 msg_factory=kw_args["msg_factory"])
        self.conv.sequence = self.sh["sequence"]
        _ent.conv = self.conv
        _ent.events = self.conv.events
        self.sh["conv"] = self.conv
        return True

    def run(self, test_id, **kw_args):
        if not self.setup(test_id, **kw_args):
            raise ConfigurationError()

        # noinspection PyTypeChecker
        try:
            return self.run_item(test_id, index=0, **kw_args)
        except Exception as err:
            exception_trace("", err, logger)
            return self.inut.err_response("run", err)

    def post_op(self, oper, res, test_id):
        """
        should be done as late as possible, so all processing has been
        :param oper:
        :return:
        """
        try:
            oper.post_tests()
        except ConditionError:
            pass

        self.conv.events.store(EV_CONDITION, State('Done', OK))
        self.store_result(res)

    def get_cls_and_func(self, index):
        item = self.conv.sequence[index]

        if isinstance(item, tuple):
            cls, funcs = item
        else:
            cls = item
            funcs = {}

        return cls, funcs

    def run_item(self, test_id, index, profiles=None, **kw_args):
        logger.info("<=<=<=<=< %s >=>=>=>=>" % test_id)

        _ss = self.sh
        try:
            _ss.test_flows.complete[test_id] = False
        except KeyError:
            pass

        self.conv.test_id = test_id
        res = Result(self.sh, self.kwargs['profile_handler'])

        if index >= len(self.conv.sequence):
            return None

        try:
            internal = kw_args['internal']
        except KeyError:
            internal = True

        cls, funcs = self.get_cls_and_func(index)

        try:
            _name = cls.__name__
        except AttributeError:
            _name = 'none'
        logger.info("<--<-- {} --- {} -->-->".format(index, _name))
        self.conv.events.store(EV_OPERATION, _name, sender='run_flow')
        try:
            _oper = cls(conv=self.conv, inut=self.inut, sh=self.sh,
                        profile=self.profile, test_id=test_id,
                        funcs=funcs, check_factory=self.chk_factory,
                        cache=self.cache, internal=internal)
            # self.conv.operation = _oper
            if profiles:
                profile_map = profiles.PROFILEMAP
            else:
                profile_map = None
            _oper.setup(profile_map)
            resp = _oper()
        except ConditionError:
            self.store_result(res)
            return False
        except Exception as err:
            exception_trace('run_flow', err)
            self.sh["index"] = index
            return self.inut.err_response("run_sequence", err)
        else:
            if isinstance(resp, self.response_cls):
                if self.conv.sequence[index+1] == Done:
                    self.post_op(_oper, res, test_id)
                return resp

            if resp:
                if self.conv.sequence[index+1] == Done:
                    self.post_op(_oper, res, test_id)
                return resp

        # should be done as late as possible, so all processing has been
        # done
        try:
            _oper.post_tests()
        except ConditionError:
            self.store_result(res)
            return False

        _ss['index'] = self.conv.index = index + 1

        return True

    def display_test_list(self, **kwargs):
        try:
            if self.sh.session_init():
                return self.inut.flow_list()
            else:
                try:
                    resp = Redirect("%s/opresult#%s" % (
                        self.base_url, self.sh["testid"][0]))
                except KeyError:
                    return self.inut.flow_list(**kwargs)
                else:
                    return resp(self.inut.environ, self.inut.start_response)
        except Exception as err:
            exception_trace("display_test_list", err)
            return self.inut.err_response("session_setup", err)

    def handle_request(self, req, path=''):
        logging.debug('Raw request: {}'.format(req))
        if req:
            self.conv.events.store(EV_REQUEST, req)
            func = getattr(self.conv.entity.server,
                           'parse_{}_request'.format(path))

            msg = None
            try:
                if req[0] in ['{', '[']:
                    msg = func(req, sformat='json')
                else:
                    if path in ['authorization', 'check_session']:
                        msg = func(query=req)  # default urlencoded
                    elif path in ['token', 'refresh_token']:
                        msg = func(body=req)
                    else:
                        msg = func(req)
            except PyoidcError as err:
                logging.error('{}'.format(err))

            if msg:
                self.conv.events.store(EV_PROTOCOL_REQUEST, msg)

    def do_config(self, sid='', start_page='', params='', **args):
        resp = Response(mako_template="config.mako",
                        template_lookup=self.kwargs['lookup'], headers=[])

        if sid:
            _url = os.path.join(self.base_url, sid)
        else:
            _url = self.base_url

        try:
            test_id = args['test_id']
        except KeyError:
            test_id = ''

        kwargs = {
            'start_page': start_page,
            'params': params,
            'issuer': _url,
            'profiles': list(self.kwargs['op_profiles'].keys()),
            'selected': self.selected,
            'sid':sid,
            'base': self.base_url,
            'test_id': test_id
        }
        return resp(self.inut.environ, self.inut.start_response, **kwargs)

    def do_next(self, req, filename, path='', **kwargs):
        sh = self.sh

        self.conv = sh['conv']
        cls, funcs = self.get_cls_and_func(self.conv.index+1)
        if cls.endpoint != path:
            if path == 'authorization':  # Jumping the gun here
                areq = AuthorizationRequest().from_urlencoded(req)
                # send an error back to the redirect_uri
                msg = AuthorizationErrorResponse(error='access_denied',
                                                 state=areq['state'])
                _entity = self.conv.entity
                redirect_uri = _entity.get_redirect_uri(areq)
                _req_loc = msg.request(redirect_uri)
                resp = _entity.server.http_request(_req_loc, 'GET')
                ret = Response('Client need to reregister')
                return ret

        self.handle_request(req, path)
        self.store_result()

        self.conv.index += 1

        try:
            resp = self.run_item(self.conv.test_id, index=self.conv.index,
                                 **kwargs)
        except Exception as err:
            raise

        if isinstance(resp, Response):
            self.store_result()
            return resp

        _done = False
        for _cond in self.conv.events.get_data(EV_CONDITION):
            if _cond.test_id == 'Done' and _cond.status == OK:
                _done = True
                break

        if not _done:
            self.conv.events.store(EV_CONDITION, State('Done', OK),
                                   sender='do_next')

            if 'assert' in self.conv.flow:
                _ver = Verify(self.chk_factory, self.conv)
                _ver.test_sequence(self.conv.flow["assert"])

            self.store_result()

        return self.inut.flow_list()

    def get_response(self, resp):
        try:
            loc = resp.headers['location']
        except (AttributeError, KeyError):  # May be a dictionary
            try:
                return resp.response
            except AttributeError:
                try:
                    return resp.text
                except AttributeError:
                    if isinstance(resp, dict):
                        return resp
        else:
            try:
                _resp = dict(
                    [(k, v[0]) for k, v in parse_qs(loc.split('?')[1]).items()])
            except IndexError:
                return loc
            else:
                self.conv.events.store(EV_RESPONSE, _resp)
                return _resp

import json
import os
import re

import logging
from six import text_type

from otest import Done
from otest import Unknown
from otest.func import factory as ofactory
from otest.summation import completed
from otest.summation import eval_state
from otest.summation import represent_result

from otest.prof_util import from_profile

logger = logging.getLogger(__name__)

PAT = re.compile('\${([A-Z_0-9]*)}')

ABBR = {
    "code": 'C',
    "id_token": 'I',
    "id_token token": 'IT',
    "code id_token": 'CI',
    "code token": 'CT',
    "code id_token token": 'CIT',
    "dynamic": 'DYN',
    "configuration": 'CNF'
}

EXP = dict([(v, k) for k, v in ABBR.items()])

GRPS = [
    "Discovery", "Dynamic Client Registration",
    "Response Type and Response Mode", "claims Request Parameter",
    "request_uri Request Parameter", "scope Request Parameter",
    "nonce Request Parameter", 'redirect_uri Request Parameter',
    'prompt Request Parameter', 'request Request Parameter',
    "Client Authentication", "OAuth behaviors",
    "ID Token", "Key Rotation", "Claims Types", "UserInfo Endpoint",
    'Misc Request Parameters', 'Key Rotation', 'Access Token',
    "Response Type", 'Response Mode'
]


def replace_with_url(txt, links):
    for m in PAT.findall(txt):
        try:
            _url = links['URL'][m]
        except KeyError:
            pass
        else:
            txt = txt.replace('${%s}' % m, _url)

    return txt


def replace_with_link(txt, links):
    for m in PAT.findall(txt):
        try:
            _url, tag = links['LINK'][m]
        except KeyError:
            pass
        else:
            _li = replace_with_url(_url, links)
            _href = '<a href="{}">{}</a>'.format(_li, tag)
            txt = txt.replace('${%s}' % m, _href)
    return txt


class Flow(object):
    def __init__(self, fdir, profile_handler):
        self.fdir = fdir
        self.profile_handler = profile_handler

    def __getitem__(self, tid):
        """
        Get the flow description given a test ID

        :param tid: The test ID
        :return: A dictionary representation of the description
        """

        fname = os.path.join(self.fdir, tid + '.json')
        fp = open(fname, 'r')
        try:
            _info = json.load(fp)
        except Exception as err:
            logger.error(err)
            raise KeyError(tid)
        finally:
            fp.close()

        return _info

    def items(self):
        """
        Return all flow descriptions.
        It is assumed that all files with names that has the postfix '.json'
        prepresents flow descriptions.

        :return:
        """
        for fn in os.listdir(self.fdir):
            if fn.endswith('.json'):
                sfn = fn[:-5]
                yield ((sfn, self[sfn]))

    def keys(self):
        """
        Return all Test IDs
        :return: list of test IDs
        """
        for fn in os.listdir(self.fdir):
            if fn.endswith('.json'):
                yield (fn[:-5])

    def pick(self, key, value):
        """
        Pick a number of test descriptions base on a key,value pair.

        :param key:
        :param value:
        :return:
        """
        tids = []
        for tid, spec in self.items():
            try:
                _val = spec[key]
            except KeyError:
                pass
            else:
                if value == _val:
                    tids.append(tid)
        return tids

    def matches_profile(self, profile):
        """
        Return a list of test IDs that all match the profile
        :param profile:
        :return:
        """

        _tids = []
        _use = from_profile(profile)
        for tid, spec in self.items():
            if match_usage(spec, **_use):
                _tids.append(tid)
        return _tids

    def mandatory_to_implement(self, tid, profile):
        _use = from_profile(profile)
        _use['return_type'] = _use['return_type'][0]
        spec = self[tid]
        try:
            _mti = spec["MTI"]
        except KeyError:
            pass
        else:
            if _use['return_type'][0] in _mti:
                if _use['register'] and 'DYN' in _mti:
                    if _use['discover'] and 'CNF' in _mti:
                        return True
        return False

    def _profile_info(self, test_id, session):
        if self.profile_handler:
            ph = self.profile_handler(session)
            try:
                return ph.get_profile_info(test_id)
            except Exception as err:
                raise
        return {}

    def __contains__(self, item):
        fname = os.path.join(self.fdir, item + '.json')
        return os.path.isfile(fname)


# ==============================================================================


def _get_cls(name, factories, use=''):
    if use:
        try:
            cls = factories[use](name)
        except Unknown:
            pass
        else:
            return cls

    try:
        cls = factories[''](name)
    except Unknown:
        raise Exception("Unknown Class: '{}'".format(name))

    return cls


def _get_func(dic, func_factory):
    """
    Convert function names into function references

    :param dic: A key, value dictionary where keys are function names
    :param func_factory: Factory function used to find functions
    :return: A dictionary with the keys replace with references to functions
    """
    res = {}
    for fname, val in dic.items():
        func = func_factory(fname)
        if func is None:
            func = ofactory(fname)

        if func is None:
            raise Exception("Unknown function: '{}'".format(fname))
        res[func] = val

    return res


class RPFlow(Flow):
    def __init__(self, fdir, profile_handler, cls_factories, func_factory,
                 use=''):
        Flow.__init__(self, fdir, profile_handler)
        self.cls_factories = cls_factories
        self.func_factory = func_factory
        self.use = use

    def expanded_conf(self, tid):
        """

        :param test_id:
        :return:
        """
        spec = self[tid]
        seq = []
        for oper in spec["sequence"]:
            if isinstance(oper, dict):  # Must be only one key, value item
                if len(oper) > 1:
                    raise SyntaxError(tid)
                key, val = list(oper.items())[0]
                try:
                    seq.append((_get_cls(key, self.cls_factories, self.use),
                                _get_func(val, self.func_factory)))
                except Exception:
                    print('tid:{}'.format(tid))
                    raise
            else:
                try:
                    seq.append(_get_cls(oper, self.cls_factories, self.use))
                except Exception:
                    print('tid:{}'.format(tid))
                    raise
        seq.append(Done)
        spec["sequence"] = seq

        return spec


def match_usage(spec, **kwargs):
    try:
        _usage = spec['usage']
    except KeyError:
        return True
    else:
        for key, allowed in _usage.items():
            try:
                val = kwargs[key]
            except KeyError:
                return False
            else:
                if key == 'return_type':
                    # val can be list of one string or just a string
                    if isinstance(val, text_type):
                        if val not in allowed:
                            return False
                    elif val[0] not in allowed:
                        return False
                else:
                    if isinstance(allowed, bool):
                        if val is not allowed:
                            return False
                    else:
                        if val not in allowed:
                            return False
    return True


def get_return_type(prof):
    try:
        return prof.split('.')[0]
    except AttributeError:
        return prof[0]


def get_category(usage):
    if 'extra' in usage:
        return '[Extra]'
    if 'register' in usage:
        return '[Dynamic]'
    if 'discover' in usage:
        return '[Config]'

    if 'return_type' not in usage:
        return '[Basic, Implicit, Hybrid]'
    else:
        li = []
        _rt = usage['return_type']
        if 'C' in _rt:
            li.append('Basic')
        if 'IT' in _rt or 'I' in _rt:
            li.append('Implicit')
        if 'CT' in _rt or 'CI' in _rt or 'CIT' in _rt:
            li.append('Hybrid')
        return '[' + ','.join(li) + ']'


class FlowState(RPFlow):
    def __init__(self, fdir, profile_handler, cls_factories, func_factory,
                 display_order, use=''):
        RPFlow.__init__(self, fdir, profile_handler, cls_factories,
                        func_factory, use=use)
        self.test_info = {}
        self.display_order = display_order
        self.complete = {}

    def store_test_info(self, tester):
        _conv = tester.conv
        tinfo = self._test_info(_conv.test_id, _conv.events, _conv.index,
                                tester.sh)
        self.test_info[_conv.test_id] = tinfo
        return tinfo

    def _test_info(self, test_id, events, index, session):
        _info = {
            'test_id': test_id,
            "events": events,
            "index": index,
            "test_output": events.get('condition'),
            "state": eval_state(events),
            "complete": completed(events),
            "result": represent_result(events)
        }

        try:
            _info["descr"] = self[test_id]["desc"]
        except KeyError:
            _info['descr'] = session['flow']['desc']

        if _info['complete']:
            self.complete[test_id] = True

        _info['profile_info'] = self._profile_info(test_id, session)

        return _info

    def display_info(self, tids):
        """
        Return information to be used in UIX display
        :param tids: List of TestIDs
        :return:
        """

        interim = {}
        for tid in tids:
            _spec = self[tid]
            try:
                _state = self.test_info[tid]['state']
            except KeyError:
                _state = 0

            try:
                interim[_spec['group']].append((_state, _spec['desc'], tid))
            except KeyError:
                interim[_spec['group']] = [(_state, _spec['desc'], tid)]

        res = []
        for grp in self.display_order:
            try:
                _s = sorted(interim[grp], key=lambda x: x[2])
            except KeyError:
                continue
            else:
                for x in _s:
                    y = [grp]
                    y.extend(x)
                    res.append(y)
        return res

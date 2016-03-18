import argparse
import importlib
import json
import logging
import os
import sys

from future.backports.urllib.parse import urlparse

from oic.utils.keyio import build_keyjar

import aatest

from aatest.summation import assert_summation
from aatest.verify import Verify

from oidctest.prof_util import map_prof

__author__ = 'roland'

logger = logging.getLogger(__name__)


def setup_logger(log, log_file_name="rp.log"):
    # logger = logging.getLogger("")
    hdlr = logging.FileHandler(log_file_name)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")

    hdlr.setFormatter(base_formatter)
    log.addHandler(hdlr)
    log.setLevel(logging.DEBUG)


def main_setup(log):
    from oidctest import profiles
    from oidctest import oper

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='flows')
    parser.add_argument('-l', dest="log_name")
    parser.add_argument('-p', dest="profile")
    parser.add_argument(dest="config")
    cargs = parser.parse_args()

    if "/" in cargs.flows:
        head, tail = os.path.split(cargs.flows)
        sys.path.insert(0, head)
        FLOWS = importlib.import_module(tail)
    else:
        FLOWS = importlib.import_module(cargs.flows)

    CONF = importlib.import_module(cargs.config)

    if cargs.log_name:
        setup_logger(log, cargs.log_name)
    else:
        setup_logger(log)

    # Add own keys for signing/encrypting JWTs
    try:
        jwks, keyjar, kidd = build_keyjar(CONF.keys)
    except KeyError:
        raise
    else:
        # export JWKS
        p = urlparse(CONF.KEY_EXPORT_URL)
        with open("." + p.path, "w") as f:
            f.write(json.dumps(jwks))
        jwks_uri = p.geturl()

    return {"base_url": CONF.BASE, "kidd": kidd,
            "jwks_uri": jwks_uri, "flows": FLOWS.FLOWS, "conf": CONF,
            "cinfo": CONF.INFO, "orddesc": FLOWS.ORDDESC,
            "profiles": profiles, "operations": oper,
            "profile": cargs.profile}


def make_list(flows, profile, **kw_args):
    f_names = list(flows.keys())
    f_names.sort()
    flow_names = []
    for k in kw_args["order"]:
        k += '-'
        l = [z for z in f_names if z.startswith(k)]
        flow_names.extend(l)

    res = []
    sprofile = profile.split(".")
    for tid in flow_names:
        _flow = flows[tid]

        if map_prof(sprofile, _flow["profile"].split(".")):
            res.append(tid)

    return res


def node_dict(flows, lst):
    return dict([(l, flows[l]) for l in lst])


def run_flow(profiles, conv, test_id, conf, profile, check_factory, io, sh,
             index=0):
    print(("==" + test_id))
    conv.test_id = test_id
    conv.conf = conf

    if index >= len(conv.flow["sequence"]):
        return None

    conv.index = index

    for item in conv.flow["sequence"][index:]:
        if isinstance(item, tuple):
            cls, funcs = item
        else:
            cls = item
            funcs = {}

        _oper = cls(conv, io, sh, profile=profile, test_id=test_id, conf=conf,
                    funcs=funcs)
        conv.operation = _oper
        _oper.setup(profiles.PROFILEMAP)
        _oper()

        conv.index += 1

    try:
        if conv.flow["assert"]:
            _ver = Verify(check_factory, conv)
            _ver.test_sequence(conv.flow["tests"])
    except KeyError:
        pass
    except Exception as err:
        aatest.exception_trace('run_flow', err, logger)
        raise

    info = assert_summation(conv.events, test_id)

    return info

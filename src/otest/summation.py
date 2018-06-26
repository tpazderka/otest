import json
import os
import tarfile

from otest.check import CRITICAL
from otest.check import ERROR
from otest.check import INCOMPLETE
from otest.check import OK
from otest.check import STATUSCODE
from otest.check import WARNING
from otest.events import EV_CONDITION
from otest.events import EV_FAULT
from otest.events import layout

__author__ = 'roland'


def assert_summation(events, sid):
    status = OK
    result = []

    if events.get_data(EV_FAULT):
        status = ERROR
    else:
        for test_result in events.get_data(EV_CONDITION):
            result.append('{}'.format(test_result))
            if test_result.status > status:
                status = test_result.status

    info = {
        "id": sid,
        "status": status,
        "assertions": result
    }

    return info


def completed(events):
    """
    Figure out if the test ran to completion
    :param events: An otest.events.Events instance
    :return: True/False
    """
    for item in events.get_data(EV_CONDITION):
        if item.test_id == "Done" and item.status in [OK, ERROR]:
            return True

    return False


def eval_state(events):
    """
    The state of the test is equal to the worst status encountered
    :param events: An otest.events.Events instance
    :return: An integer representing a status code
    """
    if completed(events):
        res = OK
    else:
        res = INCOMPLETE

    if events.get_data(EV_FAULT):
        return ERROR  # Can't get worse

    for state in events.get_data(EV_CONDITION):
        if state.status > res:
            res = state.status

    return res


def get_errors(events):
    res = []
    for item in events.get_data(EV_FAULT):
        res.append(item.message)

    for item in events.get_data(EV_CONDITION):
        if item.status in [ERROR, CRITICAL]:
            res.append(item.message)

    return '. '.join(res)


def result_code(events):
    _state = eval_state(events)
    if _state == INCOMPLETE:
        tag = "PARTIAL RESULT"
    else:
        if _state < WARNING:
            tag = "PASSED"
        else:
            tag = STATUSCODE[_state]

    return tag


def represent_result(events):
    """
    A textual representation of the status of the test result
    :param events: An otest.events.Events instance
    :return: A text string
    """

    tag = result_code(events)

    lines = [tag]

    errors = []
    warning = []
    for state in events.get_data(EV_CONDITION):
        if state.status == ERROR:
            if state.message:
                errors.append('{}'.format(state.message))
        elif state.status == WARNING:
            if state.message:
                warning.append('{}'.format(state.message))

    if errors:
        lines.append('Errors:')
        lines.append("\n".join(errors))

    if warning:
        lines.append('Warnings:')
        lines.append("\n".join(warning))

    text = "\n".join(lines)

    return text


# -----------------------------------------------------------------------------

def trace_output(events):
    """

    """
    start = 0
    element = ["Trace output\n"]
    for event in events:
        if not start:
            start = event.timestamp
        element.append(layout(start, event))
    element.append("\n")
    return element


def condition(events, html=False):
    """

    """
    if html:
        element = [""]
    else:
        element = ["Conditions\n"]
    for cond in events.get_data(EV_CONDITION):
        element.append('{}'.format(cond))
    if html:
        return "\n".join(element)
    else:
        element.append("\n")
        return element


def pprint_json(json_txt):
    _jso = json.loads(json_txt)
    return json.dumps(_jso, sort_keys=True, indent=2, separators=(',', ': '))


def mk_tar_dir(issuer, test_profile):
    wd = os.getcwd()

    # Make sure there is a tar directory
    tardirname = wd
    for part in ["tar", issuer, test_profile]:
        tardirname = os.path.join(tardirname, part)
        if not os.path.isdir(tardirname):
            os.mkdir(tardirname)

    # Now walk through the log directory and make symlinks from
    # the log files to links in the tar directory
    logdirname = os.path.join(wd, "log", issuer, test_profile)
    for item in os.listdir(logdirname):
        if item.startswith("."):
            continue

        ln = os.path.join(logdirname, item)
        tn = os.path.join(tardirname, "{}.txt".format(item))

        if os.path.isfile(tn):
            os.unlink(tn)

        if not os.path.islink(tn):
            os.symlink(ln, tn)


def create_tar_archive(issuer, test_profile):
    mk_tar_dir(issuer, test_profile)

    wd = os.getcwd()
    _dir = os.path.join(wd, "tar", issuer)
    os.chdir(_dir)

    tar = tarfile.open("{}.tar".format(test_profile), "w")

    for item in os.listdir(test_profile):
        if item.startswith("."):
            continue

        fn = os.path.join(test_profile, item)

        if os.path.isfile(fn):
            tar.add(fn)
    tar.close()
    os.chdir(wd)

import os

from otest.flow import match_usage, Flow
from otest.prof_util import from_profile

PROFILE = ['C.T.T.T.e', 'C.T.T.T.s', 'C.T.T.T.se', 'C.T.T.T.sen',
           'C.T.T.T.sen.+', 'C.T.T.F', 'C.F.T.F', 'C.T.T.T']

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "flows"))


def test_match_usage():
    assert match_usage({'usage': {'extra': True}},
                       **from_profile(PROFILE[0])) is False

    assert match_usage({"usage": {
        "return_type": ["C", "IT", "CI", "CIT", "CT"],
        "extra": True}}, **from_profile(PROFILE[0])) is False

    assert match_usage({"usage": {
        "return_type": ["C", "I", "IT", "CI", "CT", "CIT"]}},
        **from_profile(PROFILE[0]))

    assert match_usage({"usage": {
        "return_type": ["CI", "CT", "CIT"]}},
        **from_profile(PROFILE[0])) is False

    assert match_usage({"usage": {
        "return_type": ["C", "CI", "CT", "CIT"],
        "enc": True}},
        **from_profile(PROFILE[0]))


def test_flow():
    _flow = Flow(BASE_PATH, None)
    tl = _flow.matches_profile(PROFILE[0])
    assert len(tl) == 56
    tl = _flow.matches_profile(PROFILE[1])
    assert len(tl) == 62
    tl = _flow.matches_profile(PROFILE[2])
    assert len(tl) == 63
    tl = _flow.matches_profile(PROFILE[3])
    assert len(tl) == 64
    tl = _flow.matches_profile(PROFILE[4])
    assert len(tl) == 93
    tl = _flow.matches_profile(PROFILE[5])
    assert len(tl) == 41
    tl = _flow.matches_profile(PROFILE[6])
    assert len(tl) == 41
    tl = _flow.matches_profile(PROFILE[7])
    assert len(tl) == 55

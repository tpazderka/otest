from otest.flow import match_usage
from otest.prof_util import from_profile

PROFILE = ['C.T.T.T.e']


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

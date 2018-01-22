from otest.aus.preproc import PMAP


def op_choice(base, flows):
    """
    Creates a list of test flows
    """
    _grp = "_"
    color = ['<button type="button" class="btn btn-default" title="Black"><span class="glyphicon glyphicon-play"></span></button>',  # INFORMATION
             '<button type="button" class="btn btn-success" title="Green"><span class="glyphicon glyphicon-ok-sign"></span></button>',  # OK
             '<button type="button" class="btn btn-warning" title="Yellow"><span class="glyphicon glyphicon-warning-sign"></span></button>',  # WARNING
             '<button type="button" class="btn btn-danger" title="Red"><span class="glyphicon glyphicon-minus-sign"></span></button>',  # ERROR
             '<button type="button" class="btn btn-danger" title="Red"><span class="glyphicon glyphicon-minus-sign"></span></button>',  # CRITICAL
             '<button type="button" class="btn btn-default" title="QuestionMark"><span class="glyphicon glyphicon-question-sign"></span></button>',  # INTERACTION
             '<button type="button" class="btn btn-default" title="QuestionMark"><span class="glyphicon glyphicon-question-sign"></span></button>',  # INCOMPLETE
             '<button type="button" class="btn btn-default" title="Grey"><span class="glyphicon glyphicon-record"></span></button>',  # NOT_APPLICABLE
             ]
    line = [
        '<table class="table table-hover table-bordered table-condensed">',
        '<tr><th>Status</th><th>Name</th><th>Description</th><th>Info</th></tr>']

    for grp, state, desc, tid in flows:
        b = tid.split("-", 2)[1]
        if not grp == _grp:
            _grp = grp
            _item = '<td colspan="4" class="text-center info"><b>{}</b></td>'.format(_grp)
            line.append(
                '<tr id="{}">{}</tr>'.format(b, _item))

        if state:
            _info = "<a href='{}test_info/{}' class=\"btn btn-info\" role=\"button\"><span class=\"glyphicon glyphicon-info-sign\"></span></a>".format(
                base, tid)
        else:
            _info = ''

        _stat = "<a href='{}{}'>{}</a>".format(base, tid, color[state])
        line.append(
            '<tr><td>{}</td><td style="vertical-align: middle;">({})</td><td style="vertical-align: middle;">{}</td><td>{}</td></tr>'.format(
                _stat, tid, desc, _info))
    line.append('</table>')

    return "\n".join(line)


ICONS = [
    ('<button type="button" class="btn btn-default" title="Black"><span class="glyphicon glyphicon-play"></span></button>',
     "The test has not been run yet."),
    ('<button type="button" class="btn btn-success" title="Green"><span class="glyphicon glyphicon-ok-sign"></span></button>',
     "The test succeeded."),
    ('<button type="button" class="btn btn-warning" title="Yellow"><span class="glyphicon glyphicon-warning-sign"></span></button>',
     "Warning, something was not as expected."),
    ('<button type="button" class="btn btn-danger"  title="Red"><span class="glyphicon glyphicon-minus-sign"></span></button>',
     "The test failed."),
    ('<button type="button" class="btn btn-default" title="QuestionMark"><span class="glyphicon glyphicon-question-sign"></span></button>',     
     "The test flow wasn't completed. This may have been expected or not."),
    ('<button type="button" class="btn btn-info"><span class="glyphicon glyphicon-info-sign"></span></button>',
     "Signals the fact that there is trace information available for the test."),
]


def legends():
    element = ["<table class=\"table table-condensed\" id=\"legends\">"]
    for icon, txt in ICONS:
        element.append("<tr><td>%s</td><td>%s</td></tr>" % (icon, txt))
    element.append('</table>')
    return "\n".join(element)


L2I = {"webfinger": 1, "discovery": 2, "registration": 3}
CM = {"n": "none", "s": "sign", "e": "encrypt"}


def display_profile(spec):
    el = ["<table class=\"table table-condensed\">"]
    p = spec.split('.')
    el.append("<tr><td>%s</td></tr>" % PMAP[p[0]])
    for mode in ["webfinger", "discovery", "registration"]:
        if p[L2I[mode]] == "T":
            el.append("<tr><td>Dynamic %s</td></tr>" % mode)
        else:
            el.append("<tr><td>Static %s</td></tr>" % mode)
    if len(p) > 6:
        if p[6] == 'T':
            el.append("<tr><td>Form post tests</td></tr>")
    if len(p) > 4:
        if p[4]:
            el.append("<tr><td>Crypto support %s</td></tr>" % [CM[x] for x in p[4]])
    if len(p) == 6:
        if p[5] == '+':
            el.append("<tr><td>Extra tests</td></tr>")
    el.append("</table>")

    return "\n".join(el)


def display_info(info):
    line = ['<table>']
    keys = list(info['tool'].keys())
    keys.sort()
    for key in keys:
        val = info['tool'][key]
        line.append('<tr><th>{}</th><td>{}</td></tr>'.format(key, val))
    line.append('</table>')
    return '\n'.join(line)

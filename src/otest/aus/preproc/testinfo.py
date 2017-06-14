from otest import summation
from otest.events import row


def do_assertions(out):
    return summation.condition(out, True)


def trace_output(events):
    """

    """
    element = ['<table class="table table-bordered table-condensed">']
    start = 0
    for event in events:
        if not start:
            start = event.timestamp
        # element.append(layout(start, event))
        element.append(row(start, event))
    element.append("</table>")
    return "\n".join(element)


def profile_output(pinfo, version=''):
    element = ['<table class="table table-condensed">']
    for key, val in pinfo.items():
        element.append("<tr><th>%s</th><td>%s</td></tr>" % (key, val))
    element.append('</table>')
    return "\n".join(element)

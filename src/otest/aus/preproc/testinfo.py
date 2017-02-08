from otest import summation
from otest.events import layout, row


def do_assertions(out):
    return summation.condition(out, True)


def trace_output(events):
    """

    """
    element = ["<h3>Trace output</h3>", '<div class="trace"><table>']
    start = 0
    for event in events:
        if not start:
            start = event.timestamp
        # element.append(layout(start, event))
        element.append(row(start, event))
    element.append("</table></div>")
    return "\n".join(element)


def profile_output(pinfo):
    element = ['<div class="profile">']
    for key, val in pinfo.items():
        element.append("<em>%s:</em> %s<br>" % (key, val))
    element.append('</div>')
    return "\n".join(element)

import json

from otest.check import OK
from otest.check import WARNING
from otest.check import ERROR
from otest.check import CRITICAL
from otest.events import EV_CONDITION, EV_HTTP_INFO
from otest.events import EV_HTTP_RESPONSE
from otest.events import EV_PROTOCOL_RESPONSE
from otest.events import EV_FAULT
from otest.events import EV_HANDLER_RESPONSE
from otest.events import EV_HTTP_ARGS
from otest.events import EV_HTTP_RESPONSE_HEADER
from otest.events import EV_OPERATION
from otest.events import EV_PROTOCOL_REQUEST
from otest.events import EV_REDIRECT_URL
from otest.events import EV_REPLY
from otest.events import EV_REQUEST
from otest.events import EV_REQUEST_ARGS
from otest.events import EV_RESPONSE
from otest.events import EV_RESPONSE_ARGS
from otest.events import EV_SEND
from otest.events import EV_URL

__author__ = 'roland'


def adjust_lines(lines, maxlen=120):
    res = []
    for line in lines.split('\n'):
        if len(line) <= maxlen:
            res.append(line)
        else:
            n = maxlen
            for l in [line[i:i + n] for i in range(0, len(line), n)]:
                res.append(l)
    return res


def print_message(message_as_dict):
    return adjust_lines(json.dumps(message_as_dict, sort_keys=True, indent=2,
                                   separators=(',', ': ')))


BG_COLOR = {
    OK: "background-color:lightgreen;",
    WARNING: "background-color:lightyellow;",
    ERROR: "background-color:lightcoral;",
    CRITICAL: "background-color:lightcoral;"
}


def do_condition(event):
    return ['<li style="{}">{}</li>'.format(BG_COLOR[event.data.status],
                                            event.data.test_id)]


def do_protocol_response(event):
    res = ['<h4>Response</h4>', '<pre>']
    res.extend(print_message(event.data.to_dict()))
    res.append('</pre>')
    return res


def do_http_info(event):
    d = event.data
    res = ['<h4>Response</h4>',
           '<table border="1" style="width:100%">',
           '<tr><td>status</td><td>{}</td></tr>'.format(d['status']),
           '<tr><td>headers</td><td><pre>[']

    for x in d['headers']:
        res.extend(adjust_lines('{}'.format(x)))

    res.append(']</pre></td></tr>')
    res.append('<tr><td>message</td><td><pre>')
    try:
        res.extend(print_message(json.loads(d['message'])))
    except ValueError:
        res.extend(adjust_lines(d['message']))
    res.append('</pre></td></tr>')
    res.extend(['</table>'])
    return res


def do_http_response(event):
    d = event.data
    res = ['<h4>Response</h4>',
           '<table border="1" style="width:100%">',
           '<tr><td>status</td><td>{}</td></tr>'.format(d.status_code),
           '<tr><td>headers</td><td><pre>[']

    for x in d.headers:
        res.extend(adjust_lines('{}'.format(x)))

    res.append(']</pre></td></tr>')
    res.append('<tr><td>message</td><td><pre>')
    try:
        res.extend(print_message(json.loads(d.text)))
    except ValueError:
        res.extend(adjust_lines(d.text))
    res.append('</pre></td></tr>')
    res.extend(['</table>'])
    return res


def do_protocol_request(event):
    res = ['<h4>Request</h4>', '<pre>']
    res.extend(print_message(event.data.to_dict()))
    res.append('</pre>')
    return res


def do_request(event):
    res = ['<h4>Request</h4>', '<pre>']
    try:
        res.extend(print_message(json.loads(event.data)))
    except ValueError:
        res.extend(adjust_lines(event.data))
    res.append('</pre>')
    return res


def do_fault(event):
    return ()


def do_handler_response(event):
    return ()


def do_http_args(event):
    return []


def do_http_response_header(event):
    return []


def do_operation(event):
    return []


def do_request_args(event):
    return []


def do_redirect_url(event):
    return []


def do_reply(event):
    return []


def do_response(event):
    return []


def do_response_args(event):
    return []


def do_send(event):
    return []


def do_url(event):
    return []


def do_path(event):
    return ['<hr>',
            '<h3>ENDPOINT: {}</h3>'.format(event.data),
            '<hr>']


FUNC_MAP = {
    EV_CONDITION: do_condition,
    EV_FAULT: do_fault,
    EV_HANDLER_RESPONSE: do_handler_response,
    EV_HTTP_ARGS: do_http_args,
    EV_HTTP_INFO: do_http_info,
    EV_HTTP_RESPONSE: do_http_response,
    EV_HTTP_RESPONSE_HEADER: do_http_response_header,
    EV_OPERATION: do_operation,
    EV_PROTOCOL_RESPONSE: do_protocol_response,
    EV_PROTOCOL_REQUEST: do_protocol_request,
    EV_REDIRECT_URL: do_redirect_url,
    EV_REPLY: do_reply,
    EV_REQUEST: do_request,
    EV_REQUEST_ARGS: do_request_args,
    EV_RESPONSE: do_response,
    EV_RESPONSE_ARGS: do_response_args,
    EV_SEND: do_send,
    EV_URL: do_url,
    'path': do_path
}


def display(events):
    last = ''
    lines = []
    request = None
    for event in events:
        if event.typ != last:
            if event.typ == EV_CONDITION:
                lines.append('<ul>')
            elif last == EV_CONDITION:
                lines.append('</ul>')

        if request:
            if event.typ != EV_PROTOCOL_REQUEST:
                func = FUNC_MAP[request.typ]
                lines.extend(func(request))
                last = request.data
            request = None
        elif event.typ == EV_REQUEST:
            request = event
            continue
        func = FUNC_MAP[event.typ]
        lines.extend(func(event))
        last = event.typ
    return "\n".join(lines)

import json
import time

from oic.oauth2 import Message

__author__ = 'roland'

# Message direction
INCOMING = 1
OUTGOING = 2

# standard event labels
EV_ASSERTION = 'assertion'
EV_CONDITION = 'condition'
EV_EXCEPTION = 'exception'
EV_END = 'end'
EV_EVENT = 'event'
EV_FAULT = 'fault'
EV_FUNCTION = 'function'
EV_HANDLER_RESPONSE = 'handler response'
EV_HTML_SRC = 'html src'
EV_HTTP_ARGS = 'http args'
EV_HTTP_INFO = 'http info'
EV_HTTP_REQUEST = 'http request'
EV_HTTP_RESPONSE = 'http response'
EV_HTTP_RESPONSE_HEADER = 'http response header'
EV_NOOP = 'not expected to do'
EV_OPERATION = 'phase'
EV_OP_ARGS = 'operation args'
EV_PROTOCOL_RESPONSE = 'protocol response'
EV_PROTOCOL_REQUEST = 'protocol request'
EV_REDIRECT_URL = 'redirect url'
EV_REPLY = 'reply'
EV_REQUEST = 'request'
EV_REQUEST_ARGS = 'request args'
EV_RESPONSE = 'response'
EV_RESPONSE_ARGS = 'response args'
EV_RUN = 'run'
EV_SEND = 'send'
EV_URL = 'url'
EV_JWS_HEADER = 'JWS header'
EV_JWE_HEADER = 'JWE header'


class NoSuchEvent(Exception):
    pass


class Base(object):
    def __init__(self, **kwargs):
        self.op_args = kwargs

    def gather_args(self):
        return self.op_args

    def to_str(self):
        _res = self.gather_args()
        return json.dumps(_res, sort_keys=True, indent=4,
                          separators=(',', ': '))


class Operation(Base):
    def __init__(self, name, typ='', **kwargs):
        Base.__init__(self, **kwargs)
        self.name = name
        self.type = typ

    def gather_args(self):
        _res = {'name': self.name}
        if self.type:
            _res['type'] = self.type
        _res.update(Base.gather_args(self))
        return _res


class FailedOperation(Operation):
    def __init__(self, name, error, **kwargs):
        Operation.__init__(self, name, **kwargs)
        self.error = error

    def gather_args(self):
        _res = {'name': self.name, 'error': self.error}
        if self.type:
            _res['type'] = self.type
        _res.update(self.op_args)
        return _res


class HTTPRequest(Base):
    def __init__(self, endpoint, method):
        Base.__init__(self)
        self.endpoint = endpoint
        self.method = method
        self.authz = None

    def gather_args(self):
        _res = {}
        for k in ['endpoint', 'method','authz']:
            v = getattr(self, k)
            if v:
                _res[k] = v
        return _res


class HTTPResponse(object):
    def __init__(self, response):
        try:
            self.status_code = response.status_code
        except AttributeError:
            self.status_code = int(response.status.split(' ')[0])
        try:
            self.url = response.url
        except AttributeError:
            self.url = ''

        self.headers = response.headers

        # Should perhaps be more intelligent about this
        if self.status_code >= 400:
            try:
                self.text = response.text
            except AttributeError:
                self.text = response.message
        else:
            self.text = ''


class Event(object):
    def __init__(self, timestamp=0, typ='', data=None, ref='', sub='',
                 sender='', direction=0, **kwargs):
        self.timestamp = timestamp or time.time()
        self.typ = typ
        self.data = data
        try:
            self.ref = ref.lower()
        except AttributeError:
            self.ref = ref
        self.sub = sub
        self.sender = sender
        self.direction = direction
        self.kwargs = kwargs

    def __str__(self):
        return '{}:{}:{}'.format(self.timestamp, self.typ, self.data)

    def __eq__(self, other):
        if isinstance(other, Event):
            for param in ['timestamp', 'typ', 'data', 'ref', 'sub', 'sender']:
                if getattr(self, param) != getattr(other, param):
                    return False
        return True

    def older(self, other):
        if other.timestamp >= self.timestamp:
            return True
        return False

    def what_when(self):
        return '{}:{}'.format(self.timestamp, self.typ)


class Events(object):
    def __init__(self):
        self.events = []

    def store(self, typ, data, ref='', sub='', sender='', direction=0,
              **kwargs):
        index = time.time()

        typ = typ.lower()
        if typ == EV_HTTP_RESPONSE:  # only store part of the instance
            data = HTTPResponse(data)

        self.events.append(
            Event(int(index), typ, data, ref, sub, sender, direction, **kwargs))
        return index

    def by_index(self, index):
        l = [e for e in self.events if e.timestamp == index]
        if l:
            return l[0]
        else:
            raise KeyError(index)

    def by_ref(self, ref):
        try:
            lr = ref.lower()
        except AttributeError:
            lr = ref
        return [e for e in self.events if e.ref == lr]

    def by_direction(self, direction):
        return [e for e in self.events if e.direction == direction]

    def get(self, typ):
        ltyp = typ.lower()
        return [ev for ev in self.events if ev.typ == ltyp]

    def get_data(self, typ, sender=''):
        if sender:
            return [d.data for d in self.get(typ) if d.sender == sender]
        else:
            return [d.data for d in self.get(typ)]

    def get_messages(self, typ, msg_cls):
        res = []
        for m in self.get(typ):
            if m.data.__class__ == msg_cls:
                res.append(m.data)
        # return [m.data for m in self.get(typ) if isinstance(m.data, msg_cls)]
        return res

    def last(self, typ):
        res = self.get(typ)
        if len(res):
            return res[-1]
        else:
            return None

    def get_message(self, typ, msg_cls):
        l = self.get_messages(typ, msg_cls)
        if l:
            return l[-1]

        raise NoSuchEvent('{}:{}'.format(typ, msg_cls))

    def last_item(self, typ):
        l = self.get_data(typ)
        if l:
            return l[-1]

        raise NoSuchEvent(typ)

    def __len__(self):
        return len(self.events)

    def __getitem__(self, item):
        return self.get_data(item)

    def __setitem__(self, key, value):
        self.store(key, value)

    def append(self, event):
        assert isinstance(event, Event)
        self.events.append(event)

    def extend(self, events):
        for event in events:
            self.append(event)

    def __iter__(self):
        return self.events.__iter__()

    def last_of(self, types):
        l = self.events[:]
        l.reverse()
        for ev in l:
            if ev.typ in types:
                return ev.data

        return None

    def __contains__(self, event):
        ts = event.timestamp
        for ev in self.events:
            if event.timestamp == ev.timestamp:
                if event == ev:
                    return True

        return False

    def sort(self):
        self.events.sort(key=lambda event: event.timestamp)

    def to_html(self, form='table'):
        if form == 'list':
            text = ['<ul>']
            for ev in self.events:
                text.append('<li> {}'.format(ev))
            text.append('</ul>')
        else:
            text = ['<table border=1 width="600">']
            for ev in self.events:
                if isinstance(ev.data, Message):
                    _data = json.dumps(ev.data.to_dict(), sort_keys=True,
                                       indent=4, separators=(',', ': '))
                else:
                    _data = ev.data
                text.append(
                    '<tr><td>{time}</td><td>{typ}</td>'
                    '<td>{data}}</td></tr>'.format(
                        time=ev.timestamp, typ=ev.typ, data=_data))
            text.append('</table>')

        return '\n'.join(text)

    def __str__(self):
        return '\n'.join(['{}'.format(ev) for ev in self.events])

    def reset(self):
        self.events = []

    def when(self, typ, msg):
        res = []
        for m in self.get(typ):
            if m.data.__class__ == msg:
                res.append(m.timestamp)

        return res

    def last_event_type(self):
        return self.events[-1].typ

    def timeline(self):
        start = self.events[0].timestamp
        return [(ev.timestamp - start, ev.typ, ev.data) for ev in self.events]

    def digest(self):
        res = []
        for event in self.events:
            res.append(event.what_when())
        return res


def funtion_to_str(event):
    _dat = event.data
    res = [_dat['name']]
    if 'args' in _dat and _dat['args']:
        res.append('args:{}'.format(_dat['args']))
    if 'kwargs' in _dat and _dat['kwargs']:
        res.append('kwargs:{}'.format(_dat['kwargs']))
    return res


def http_response_to_str(event):
    _dat = event.data
    res = [event.typ]
    if _dat.url:
        res.append('url:{}'.format(_dat.url))
    if _dat.status_code:
        res.append('status_code:{}'.format(_dat.status_code))
    if _dat.text:
        res.append('message:{}'.format(_dat.text))
    return res


def exception_to_str(event):
    res = [event.typ]
    try:
        res.append('{} {}'.format(event.kwargs['note'], event.data))
    except KeyError:
        res.append('{}'.format(event.data))
    return res


def message_to_str(event):
    return [event.data.__class__.__name__,
            json.dumps(event.data.to_dict(), sort_keys=True, indent=4,
                       separators=(',', ': '))]


TO_STR = {
    EV_FUNCTION: funtion_to_str,
    EV_HTTP_RESPONSE: http_response_to_str,
    EV_EXCEPTION: exception_to_str,
    EV_PROTOCOL_REQUEST: message_to_str,
    EV_PROTOCOL_RESPONSE: message_to_str
}


def layout(start, event):
    elem = ['{}'.format(round(event.timestamp - start, 3))]
    if event.direction:
        if event.direction == OUTGOING:
            elem.append('-->')
        else:
            elem.append('<--')

    try:
        elem.extend(TO_STR[event.typ](event))
    except KeyError:
        elem.append(event.typ)
        if isinstance(event.data, Base):
            elem.append(event.data.to_str())
        else:
            elem.append(str(event.data))

    return ' '.join(elem)


def row(start, event):
    if event.typ == EV_OPERATION:
        _row = ['<tr class="info"><td>{}</td>'.format(
            round(event.timestamp - start, 3))]
    else:
        _row = ['<tr><td>{}</td>'.format(
            round(event.timestamp - start, 3))]

    try:
        p = TO_STR[event.typ](event)
        _row.append(
            '<td>{}</td><td><pre><code>{}</pre></code></td>'.format(
                p[0],' '.join(p[1:])))
    except KeyError:
        _row.append('<td style="max-width: 500px; word-wrap: break-word;">{}</td>'.format(event.typ))
        if isinstance(event.data, Base):
            _row.append('<td style="max-width: 500px; word-wrap: break-word;">{}</td>'.format(event.data.to_str()))
        else:
            _row.append('<td style="max-width: 500px; word-wrap: break-word;">{}</td>'.format(str(event.data)))
    _row.append("</tr>")
    return "".join(_row)
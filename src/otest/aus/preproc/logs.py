preline = "<h3>A list of {} that are saved on disk for this {}:</h3>"


def display_log(logs, issuer, profile, base):
    el = []
    if issuer:
        if profile:
            el.append(preline.format('tests', 'profile'))
        else:
            el.append(preline.format('profiles', 'issuer'))
    else:
        el.append(preline.format('issuers', 'test server'))

    el.append("<ul>")

    if profile:
        for name, path in logs:
            el.append(
                '<li><a href="{}{}" download="{}.html">{}</a>'.format(
                    base, path, name, name))
    elif 'issuer':
        for name, path in logs:
            _tarfile = "{}{}.tar".format(base, path.replace("log", "tar"))
            el.append(
                '<li><a href="{}{}">{}</a> tar file:<a href="{}">'.format(
                    base, path, name, _tarfile))
            el.append('Download logs</a>')
    else:
        for name, path in logs:
            el.append('<li><a href="{}{}">{}</a>'.format(base, path, name))
    el.append("</ul>")
    return '\n'.join(el)

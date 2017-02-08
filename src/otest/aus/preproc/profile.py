from otest.aus.preproc import PMAP

PMAPL = list(PMAP.keys())
PMAPL.sort()

L2I = {"discovery": 1, "registration": 2}
CRYPTSUPPORT = {"none": "n", "signing": "s", "encryption": "e"}


def profile_form(prof):
    p = prof.split(".")
    el = []
    for key in PMAPL:
        txt = PMAP[key]
        if key == p[0]:
            el.append(
                '<input type="radio" name="rtype" value="%s" checked>%s<br>' % (
                    key, txt))
        else:
            el.append('<input type="radio" name="rtype" value="%s">%s<br>' % (
                key, txt))
    el.append("<br>")
    el.append("These you can't change here:")
    el.append("<ul>")
    for mode in ["discovery", "registration"]:
        if p[L2I[mode]] == "T":
            el.append("<li>Dynamic %s" % mode)
        else:
            el.append("<li>Static %s" % mode)
    el.append("</ul><p>Cryptographic support:<br>")
    if len(p) == 3:
        vs = "sen"
    else:
        if p[3] == '':
            vs = "sen"
        else:
            vs = p[3]
    for name, typ in CRYPTSUPPORT.items():
        if typ in vs:
            el.append('<input type="checkbox" name="%s" checked>%s<br>' % (
                name, name))
        else:
            el.append('<input type="checkbox" name="%s">%s<br>' % (name, name))
    el.append("</p>")
    el.append(
        '</ul><p>Check this if you want extra tests (not needed for any '
        'certification profiles): ')
    if len(p) == 5 and p[4] == "+":
        el.append('<input type="checkbox" name="extra" checked>')
    else:
        el.append('<input type="checkbox" name="extra">')
    el.append('</p>')
    return "\n".join(el)

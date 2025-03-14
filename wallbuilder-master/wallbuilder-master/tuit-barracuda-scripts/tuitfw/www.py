from importlib import import_module
from ipaddress import ip_network
import logging
import os
import sys
from wsgiref.handlers import CGIHandler
import jinja2
from werkzeug.exceptions import BadRequest
from werkzeug.wrappers import Request, Response
from .common import diff_firewall_services, load_config
from .loggage import UnboundedMemoryHandler


DEFAULT_WEB_CONFIG_FILE = "wwwconfig.yaml"
TEMPLATES = {
    'base.html': """<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8" />
<title>{% block title %}Tohne Itel{% endblock %}</title>
<link rel="stylesheet" type="text/css" href="static/style.css?20210527-01" />
</head>
<body>
<h1>{{ self.title() }}</h1>
{% if motd|default(none) is not none %}
<p class="motd">{{ motd }}</p>
{% endif %}
{% block body %}
{% endblock %}
</body>
</html>
""",

    'index.html': """
{% extends 'base.html' %}
{% block title %}TU-Firewall{% endblock %}
{% block body %}
<table>
  <tr>
    <td><a href="fwlist.py">Freischaltungen TU-Firewall</a></td>
    <td><a href="diff.py">&larr; Unterschiede &rarr;</a></td>
    <td><a href="dblist.py">Freischaltungen TUNET-Datenbank</a></td>
  </tr>
</table>
<p>
  <a href="update.py">Freischaltungen au&szlig;ertourlich &uuml;bertragen</a> (Benutzer
  <em>update</em>, starkes Passwort nach KOMvention)
</p>
{% endblock %}
""",

    'list.html': """
{% extends 'base.html' %}
{% block body %}
<!--
Filteroptionen (URL-Parameter):
service: Dienstgruppe
ipbegin: Anfang der IP-Adresse
subnet: IP-Subnetz
-->

{% if filters %}
<p class="filter">gefiltert nach {% for (descr, key) in filters %}{% if not loop.first %}, {% endif %}<span class="{{ key|e }}">{{ descr|e }}</span>{% endfor %}</p>
{% endif %}
<table>
 <tr>
  <th class="service">Dienstgruppe</th>
  <th class="address">Adresse</th>
  <th class="comment">Kommentar</th>
 </tr>
 {% for service, service_entries in entries %}
   {% for entry in service_entries %}
     <tr>
       <td class="service">{{ service|escape }}</td>
       <td class="address">{{ entry.ip_string|escape }}</td>
       <td class="comment">{{ entry.comment|escape }}</td>
     </tr>
   {% endfor %}
 {% endfor %}
</table>
{% endblock %}
""",

    'dblist.html': """
{% extends 'list.html' %}
{% block title %}Freischaltungen in der TUNET-Datenbank{% endblock %}
""",

    'fwlist.html': """
{% extends 'list.html' %}
{% block title %}Freischaltungen auf der TU-Firewall{% endblock %}
""",

    'diff.html': """
{% extends 'base.html' %}
{% block title %}geplante &Auml;nderungen auf der TU-Firewall{% endblock %}
{% block body %}
<table>
 <tr>
  <th class="service">Dienst</th>
  <th class="change">&Auml;nderung</th>
  <th class="address">Adresse</th>
  <th class="comment-old">Kommentar alt</th>
  <th class="comment-new">Kommentar neu</th>
 </tr>
 {% for service, diff in service_diffs.items() %}
   {% for op, old_entry, new_entry in diff %}
     <tr>
      <td class="service">{{ service|escape }}</td>
      <td class="change">{{ op|escape }}</td>
      <td class="address">{% if old_entry is not none %}{{ old_entry.ip_string|escape }}{% elif new_entry is not none %}{{ new_entry.ip_string|escape }}{% endif %}</td>
      <td class="comment-old">{% if old_entry is not none %}{{ old_entry.comment|escape }}{% endif %}</td>
      <td class="comment-new">{% if new_entry is not none %}{{ new_entry.comment|escape }}{% endif %}</td>
     </tr>
   {% endfor %}
 {% endfor %}
</table>
{% endblock %}
""",

    'update-verify.html': """
{% extends 'base.html' %}
{% block title %}Aktualisierung der Freischaltungen auf TU-Firewall{% endblock %}
{% block body %}
<p>Hiermit werden die Freischaltungen auf der TU-Firewall sofort aus der TUNET-Datenbank in die
TU-Firewall &uuml;bernommen.</p>
<form action="" method="post">
<p>
 <label for="tufw-iunderstand1">
  <input id="tufw-iunderstand1" name="iunderstand1" value="yes" type="checkbox" required="required" />
  Ich habe einen guten Grund die Freischaltungen au&szlig;ertourlich aktualisieren zu lassen.
 </label>
</p>
<p>
 <label for="tufw-iunderstand2">
  <input id="tufw-iunderstand2" name="iunderstand2" value="yes" type="checkbox" required="required" />
  Es ist mir klar, dass es wom&ouml;glich Freischaltungen von anderen Admins gibt, die nicht mit
  einer au&szlig;ertourlichen Aktualisierung rechnen.
 </label>
</p>
<p>
 <label for="tufw-iunderstand3">
  <input id="tufw-iunderstand3" name="iunderstand3" value="yes" type="checkbox" required="required" />
  Ich verspreche im Anschluss an die Aktualisierung der Firewallregeln einen KOMLOG-Eintrag zu
  verfassen.
 </label>
</p>
<p><input type="submit" value="Na dann wollen wir mal" /></p>
</form>
{% endblock %}
""",

    'update-unverified.html': """
{% extends 'base.html' %}
{% block title %}Aktualisierung der Freischaltungen auf TU-Firewall{% endblock %}
{% block body %}
<p>Sie m&uuml;ssen allen Aussagen zustimmen, bevor die Freischaltungen aktualisiert werden
k&ouml;nnen.</p>
{% endblock %}
""",

    'update-done.html': """
{% extends 'base.html' %}
{% block title %}Freischaltungen auf TU-Firewall aktualisiert{% endblock %}
{% block body %}
<p>Die Freischaltungen wurden aktualisiert.</p>
<p>KOMLOG-Eintrag nicht vergessen! (Versprochen ist versprochen!)</p>
{% endblock %}
""",
}


def respond_template(template_name, status=200, **variables) -> Response:
    loader = jinja2.DictLoader(TEMPLATES)
    env = jinja2.Environment(
            loader=loader,
            undefined=jinja2.StrictUndefined
    )
    tpl = env.get_template(template_name)

    rendered = tpl.render(**variables)

    return Response(
        [rendered],
        mimetype='text/html',
        status=status,
    )


def load_web_config():
    web_config_filename = os.environ.get('TUITFW_WEB_CONFIG', DEFAULT_WEB_CONFIG_FILE)
    return load_config(web_config_filename)


def get_motd(config):
    return config.get("www", {}).get("motd", None)


def sorted_entries(entries):
    ret = []
    for (service, service_entries) in sorted(entries.items(), key=lambda kv: kv[0]):
        sorted_service_entries = sorted(service_entries, key=lambda ent: ent.comparison_key)
        ret.append((service, sorted_service_entries))
    return ret


def obtain_db_entries(config):
    cmdb_module = import_module('.cmdb.' + config['cmdb']['type'], __package__)
    with cmdb_module.connect_to_database_from_config(config) as db_conn:
        db_entries = cmdb_module.obtain_database_entries(db_conn, config)

    fw_type = config.get('firewall', {}).get('type', None)
    if fw_type is not None:
        firewall_module = import_module('.fw.' + config['firewall']['type'], __package__)
        firewall_session = firewall_module.make_api_session(config)
        firewall_session.consolidate_entries(db_entries)

    return db_entries


def obtain_fw_entries(config):
    #type: ignore[attr-defined]
    firewall_module = import_module('.fw.' + config['firewall']['type'], __package__)
    firewall_session = firewall_module.make_api_session(config)
    firewall_session.login()
    entries = firewall_session.obtain_firewall_entries()
    firewall_session.logout()
    return entries


def is_supernet_or_equal(subnet, candidate_supernet):
    if subnet.version != candidate_supernet.version:
        return False
    return (
        subnet.network_address in candidate_supernet
        and subnet.broadcast_address in candidate_supernet
    )


def maybe_filtered_entries(entry_list, arg_dict):
    wanted_service = arg_dict.get('service', None)
    wanted_ipbegin = arg_dict.get('ipbegin', None)
    wanted_subnet = arg_dict.get('subnet', None)

    if all(flt is None for flt in (wanted_service, wanted_ipbegin, wanted_subnet)):
        # no change
        return entry_list

    if wanted_service is not None:
        wanted_service = wanted_service.lower()
    if wanted_ipbegin is not None:
        wanted_ipbegin = wanted_ipbegin.lower()
    if wanted_subnet is not None:
        try:
            wanted_subnet = ip_network(wanted_subnet, strict=False)
        except ValueError:
            # pylint: disable=raise-missing-from
            raise BadRequest(
                "Die Option 'subnet', wenn angegeben, muss eine g\u00FCltige IP-Adresse (etwa"
                " '127.0.0.1' oder '::1') oder IP-Subnetzangabe (etwa '127.0.0.0/8' oder"
                " '127.0.0.0/255.0.0.0' oder 'fe80::/16') sein."
            )

    return [
        (
            service,
            [
                entry
                for entry
                in entries
                if
                    (
                        wanted_ipbegin is None
                        or entry.ip_string.startswith(wanted_ipbegin)
                    )
                    and
                    (
                        wanted_subnet is None
                        or is_supernet_or_equal(ip_network(entry.ip_string), wanted_subnet)
                    )
            ],
        )
        for (service, entries)
        in entry_list
        if
            (
                wanted_service is None
                or service.lower() == wanted_service
            )
    ]


def collect_filters(req_args):
    return [
        (name_fmt.format(req_args[key]), key)
        for (name_fmt, key)
        in (
            ("Dienstgruppe {0!r}", 'service'),
            ("IP-Adressanfang {0!r}", 'ipbegin'),
            ("IP-Subnetz {0!r}", 'subnet'),
        )
        if key in req_args
    ]


@Request.application
def get_index(request: Request) -> Response:
    #pylint: disable=unused-argument
    config = load_web_config()
    motd = get_motd(config)
    return respond_template('index.html', motd=motd)


@Request.application
def get_dblist(request: Request) -> Response:
    config = load_web_config()
    motd = get_motd(config)
    obj_to_entries = obtain_db_entries(config)
    sorted_entry_list = maybe_filtered_entries(
        sorted_entries(obj_to_entries),
        request.args,
    )
    filters = collect_filters(request.args)
    return respond_template(
        'dblist.html',
        motd=motd,
        entries=sorted_entry_list,
        filters=filters,
    )


@Request.application
def get_dbcheck(request: Request) -> Response:
    #pylint: disable=unused-argument

    # capture logging
    root_logger = logging.getLogger()
    log_handler = UnboundedMemoryHandler()
    root_logger.addHandler(log_handler)

    config = load_web_config()
    _ = obtain_db_entries(config)

    max_error_level = max(
        (rec.levelno for rec in log_handler.records),
        default=0
    )
    icinga_exit_code = 0
    if max_error_level >= logging.ERROR:
        icinga_exit_code = 2
    elif max_error_level >= logging.WARNING:
        icinga_exit_code = 1

    messages = []
    if log_handler.records:
        for rec in log_handler.records:
            message = rec.getMessage()
            messages.append(f"{message}\r\n")
    else:
        messages.append("all entries OK\r\n")

    return Response(
        messages,
        mimetype='text/plain',
        headers=[
            ('X-Icinga-Exit-Code', f'{icinga_exit_code}'),
        ],
    )


@Request.application
def get_fwlist(request: Request) -> Response:
    config = load_web_config()
    motd = get_motd(config)
    obj_to_entries = obtain_fw_entries(config)
    sorted_entry_list = maybe_filtered_entries(
        sorted_entries(obj_to_entries),
        request.args,
    )
    filters = collect_filters(request.args)
    return respond_template(
        'fwlist.html',
        motd=motd,
        entries=sorted_entry_list,
        service_filter=request.args.get('service', None),
        filters=filters,
    )


@Request.application
def get_diff(request: Request) -> Response:
    #pylint: disable=unused-argument
    config = load_web_config()
    motd = get_motd(config)
    db_obj_to_entries = obtain_db_entries(config)
    fw_obj_to_entries = obtain_fw_entries(config)

    service_diffs = diff_firewall_services(fw_obj_to_entries, db_obj_to_entries)
    return respond_template(
        'diff.html',
        motd=motd,
        service_diffs=service_diffs,
    )


def get_update(request: Request) -> Response:
    #pylint: disable=unused-argument
    config = load_web_config()
    motd = get_motd(config)
    return respond_template('update-verify.html', motd=motd)


def post_update(request: Request) -> Response:
    #pylint: disable=unused-argument

    VERIFY_COUNT = 3

    for n in range(1, VERIFY_COUNT+1):
        if request.form.get(f'iunderstand{n}', None) != 'yes':
            return respond_template('update-unverified.html', status=400)

    # and GO
    config = load_web_config()
    motd = get_motd(config)
    db_obj_to_entries = obtain_db_entries(config)

    firewall_module = import_module('.fw.' + config['firewall']['type'], __package__)
    firewall_session = firewall_module.make_api_session(config)
    firewall_session.login()

    fw_obj_to_entries = firewall_session.obtain_firewall_entries()

    diffs = diff_firewall_services(fw_obj_to_entries, db_obj_to_entries)

    for service_name, diff in sorted(diffs.items()):
        firewall_session.implement_diff_on_firewall(
                diff, service_name, {4, 6}
        )

    firewall_session.commit_changes()

    # history
    history_config = config.get('history', None)
    if history_config is not None:
        history_module = import_module('.history.' + history_config['type'], __package__)
        fresh_obj_to_firewall_entries = firewall_session.obtain_firewall_entries()
        remote_addr = os.environ.get('REMOTE_ADDR', 'unknown address')
        history_module.remember( #type: ignore[attr-defined]
            fresh_obj_to_firewall_entries,
            history_config,
            f"manual update through web interface from {remote_addr}",
        )

    firewall_session.logout()

    return respond_template('update-done.html', motd=motd)


@Request.application
def handle_update(request: Request) -> Response:
    if request.method == 'POST':
        return post_update(request)
    else:
        return get_update(request)


def run(app_callable):
    # normalize the environment if we are running locally
    if 'QUERY_STRING' not in os.environ:
        os.environ['QUERY_STRING'] = " ".join(sys.argv[1:])
    if 'REQUEST_METHOD' not in os.environ:
        os.environ['REQUEST_METHOD'] = 'GET'

    # run under the WSGI CGI handler
    CGIHandler().run(app_callable)

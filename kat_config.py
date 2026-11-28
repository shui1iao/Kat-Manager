"""Kat-Manager strict reader: the bounded single-node management contract
for SS / AnyTLS / Trojan / SOCKS5 configurations and kat-<kind>.service units.
Unknown shapes are unsupported, never a signal to install or infer a backend.
"""
import base64
import ipaddress
import json
import re
from urllib.parse import urlsplit

MAX_BYTES = 1 << 20  # the core's configuration size limit
ERROR = 'Kat 配置/单元不完整、不支持或后端冲突；已拒绝自动变更'
METHODS = {'2022-blake3-aes-128-gcm': 16, '2022-blake3-aes-256-gcm': 32,
           '2022-blake3-chacha20-poly1305': 32, 'aes-128-gcm': 0,
           'aes-256-gcm': 0, 'chacha20-ietf-poly1305': 0}
SAFE_PATH = re.compile(r'/[A-Za-z0-9_./+-]+\Z')
REMOVED_TOP_KEYS = frozenset(('routing', 'outbounds', 'groups', 'providers', 'rule_sets', 'geoip', 'geosite', 'asn'))
MAX_DNS_SERVERS = 16


def reject():
    raise ValueError(ERROR)


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            reject()
        result[key] = value
    return result


def loads(raw):
    if not isinstance(raw, str) or len(raw.encode()) > MAX_BYTES:
        reject()
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: reject())


def shape(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        reject()


def text(value):
    if not isinstance(value, str) or not value or len(value.encode()) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        reject()
    return value


def listen(value):
    text(value)
    match = re.fullmatch(r'(\[[^]\[]+\]|[^:]+):([0-9]+)', value)
    if not match:
        reject()
    raw_host, p = match.groups()
    host = raw_host[1:-1] if raw_host.startswith('[') else raw_host
    ip = ipaddress.ip_address(host)
    if (ip.version == 6) != raw_host.startswith('['):
        reject()
    if not p.isascii() or not p.isdigit() or not 1 <= int(p) <= 65535:
        reject()
    return host, int(p)


def credential(method, value):
    text(value)
    if method not in METHODS:
        reject()
    if METHODS[method]:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != METHODS[method] or base64.b64encode(raw).decode() != value:
            reject()
    return value


def domain_name(value):
    # Validate a DNS ASCII name without normalizing the user's stored value.
    if not isinstance(value, str) or not value or not value.isascii():
        reject()
    name = value[:-1] if value.endswith('.') else value
    if not name or len(name) > 253:
        reject()
    for label in name.split('.'):
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label):
            reject()


def dns_host(value):
    if not value or '%' in value:
        reject()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        # A malformed dotted IP must not become a guessed hostname.
        if '.' in value and re.fullmatch(r'[0-9.]+', value):
            reject()
        domain_name(value)


def dns_endpoint(value, url=False):
    if not value:
        reject()
    if value.startswith('['):
        host, close, rest = value[1:].partition(']')
        if not close or '%' in host or ipaddress.ip_address(host).version != 6:
            reject()
        if rest:
            if not rest.startswith(':'):
                reject()
            p = rest[1:]
        else:
            p = None
    else:
        # A literal bare IPv6 address has no port. URL IPv6 needs brackets.
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            ip = None
        if ip is not None:
            if '%' in value or (url and ip.version == 6):
                reject()
            return
        if value.count(':') > 1:
            reject()
        host, sep, p = value.partition(':')
        p = p if sep else None
        dns_host(host)
    if p is not None and (not p.isascii() or not p.isdigit() or not 1 <= int(p) <= 65535):
        reject()


def dns_server_entry(server, allow_system=False):
    if not isinstance(server, str) or not server or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in server):
        reject()
    if server == 'system':
        if not allow_system:
            reject()
        return
    if any(c in server for c in ('?', '#', '\\')):
        reject()
    if '://' not in server:
        dns_endpoint(server)
        return
    # Use URL parsing only for syntax; no resolution, HTTP or normalization.
    scheme = server.split('://', 1)[0].lower()
    if scheme not in ('udp', 'tcp', 'https'):
        reject()
    parsed = urlsplit(server)
    if parsed.scheme != scheme or not parsed.netloc or '@' in parsed.netloc or parsed.query or parsed.fragment:
        reject()
    dns_endpoint(parsed.netloc, url=True)
    if scheme == 'https':
        if not parsed.path or not parsed.path.startswith('/') or re.search(r'%(?![0-9A-Fa-f]{2})', parsed.path):
            reject()
    elif parsed.path:
        reject()


def dns_config(value):
    strict(value, (), ('server', 'servers', 'cache_entries'))
    if 'server' in value and 'servers' in value:
        reject()
    system_only = False
    if 'server' in value:
        dns_server_entry(value['server'], allow_system=True)
        system_only = (value['server'] == 'system')
    elif 'servers' in value:
        servers = value['servers']
        if not isinstance(servers, list) or not 1 <= len(servers) <= MAX_DNS_SERVERS:
            reject()
        for entry in servers:
            dns_server_entry(entry, allow_system=False)
    if 'cache_entries' in value:
        cache = value['cache_entries']
        if type(cache) is not int or not 0 <= cache <= 4096 or (system_only and cache != 0):
            reject()


def strict(value, required, optional=()):
    # New blocks follow the core's strict JSON: no unknown keys, no explicit null.
    shape(value, required, optional)
    if any(item is None for item in value.values()):
        reject()
    return value


NS = 1000000000
GO_UNITS = {'ns': 1, 'us': 1000, '\u00b5s': 1000, '\u03bcs': 1000, 'ms': 1000000, 's': NS, 'm': 60 * NS, 'h': 3600 * NS}


def go_bool(value):
    if type(value) is not bool:
        reject()
    return value


def go_duration(value):
    """Go time.ParseDuration; returns nanoseconds."""
    if not isinstance(value, str):
        reject()
    s, negative, total, limit = value, False, 0, 1 << 63
    if s and s[0] in '+-':
        negative, s = s[0] == '-', s[1:]
    if s == '0':
        return 0
    if not s:
        reject()
    while s:
        if not (s[0] == '.' or '0' <= s[0] <= '9'):
            reject()
        i = v = 0
        while i < len(s) and '0' <= s[i] <= '9':
            if v > limit // 10:
                reject()
            v = v * 10 + ord(s[i]) - 48
            if v > limit:
                reject()
            i += 1
        pre, s = i > 0, s[i:]
        f, scale, post = 0, 1.0, False
        if s and s[0] == '.':
            s, i, overflow = s[1:], 0, False
            while i < len(s) and '0' <= s[i] <= '9':
                if not overflow:
                    if f > (limit - 1) // 10 or f * 10 + ord(s[i]) - 48 > limit:
                        overflow = True
                    else:
                        f, scale = f * 10 + ord(s[i]) - 48, scale * 10
                i += 1
            post, s = i > 0, s[i:]
        if not pre and not post:
            reject()
        i = 0
        while i < len(s) and not (s[i] == '.' or '0' <= s[i] <= '9'):
            i += 1
        unit, s = GO_UNITS.get(s[:i]), s[i:]
        if unit is None or v > limit // unit:
            reject()
        v *= unit
        if f > 0:
            v += int(float(f) * (float(unit) / scale))
            if v > limit:
                reject()
        total += v
        if total > limit:
            reject()
    if negative:
        return -total
    if total > limit - 1:
        reject()
    return total


# Kat core Limits (kernel/config.go) and AnyTLS identity budgets
# (kernel/anytls.go normalize), identical static ranges in 0.6.0..0.6.2; only
# the defaults differ. 0 means "core default". Version-dependent cross-field
# rules (sum of AnyTLS max_streams vs logical_streams) are left to `kat check`.
MAX_DATAGRAM = 65507
LIMIT_INTS = {'logical_streams': (1, 65536), 'connections': (1, 65536), 'handshakes': (1, 65536),
              'dials': (1, 65536), 'udp_associations': (1, 65536), 'pool_buffers': (1, 65536),
              'udp_queue': (1, 256), 'udp_targets': (1, 1024), 'buffer_size': (1024, 65536),
              'udp_queue_bytes': (1, 256 * MAX_DATAGRAM), 'udp_fragment_bytes': (512, MAX_DATAGRAM)}
LIMIT_TIMEOUTS = ('handshake_timeout', 'dial_timeout', 'drain_timeout', 'udp_idle')
LIMIT_KEYS = tuple(LIMIT_INTS) + LIMIT_TIMEOUTS + ('tcp_idle', 'disable_fast_path')
ANYTLS_INTS = {'max_sessions': (1, 65536), 'max_streams': (1, 65536), 'session_streams': (1, 64),
               'stream_bytes': (65542, 4 << 20), 'session_bytes': (1, 16 << 20)}
ANYTLS_KEYS = tuple(ANYTLS_INTS) + ('slow_timeout', 'padding_scheme')


def padding_int(raw):
    if not raw or not raw.isascii() or not re.fullmatch(r'\+?[0-9]+', raw):
        reject()
    return int(raw)


def padding_scheme(value):
    """anytls.ValidatePaddingScheme(s, 4096); empty string selects DefaultPaddingScheme."""
    if not isinstance(value, str) or len(value.encode('utf-8')) > 4096:
        reject()
    if value == '':
        return
    lines = value.split('\n')
    if len(lines) > 66:
        reject()
    seen = {}
    seen_idx = set()
    stop = -1
    for line in lines:
        parts = line.split('=', 1)
        if len(parts) != 2 or parts[0] in seen:
            reject()
        key, body = parts
        seen[key] = True
        if key == 'stop':
            stop = padding_int(body)
            if not 1 <= stop <= 64:
                reject()
            continue
        index = padding_int(key)
        if not 0 <= index < 64 or index in seen_idx:
            reject()
        seen_idx.add(index)
        tokens = body.split(',')
        if not 1 <= len(tokens) <= 32 or (index == 0 and len(tokens) != 1):
            reject()
        for token in tokens:
            if token == 'c' and index != 0:
                continue
            bounds = token.split('-')
            if len(bounds) != 2:
                reject()
            lo, hi = padding_int(bounds[0]), padding_int(bounds[1])
            if not 0 <= lo <= hi <= 65535:
                reject()
    if stop < 0:
        reject()
    for index in seen_idx:
        if index >= stop:
            reject()


def budget(value, low, high):
    # 0 = core default; otherwise the core's hard range. JSON floats/bools fail.
    if type(value) is not int or (value and not low <= value <= high):
        reject()
    return value


def limits_config(limits):
    strict(limits, (), LIMIT_KEYS)
    for key, (low, high) in LIMIT_INTS.items():
        if key in limits:
            budget(limits[key], low, high)
    for key in LIMIT_TIMEOUTS:
        if key in limits:
            value = go_duration(limits[key])
            if value and not 1000000 <= value <= 24 * 3600 * NS:
                reject()
    if 'tcp_idle' in limits and not 0 <= go_duration(limits['tcp_idle']) <= 24 * 3600 * NS:
        reject()
    if 'disable_fast_path' in limits:
        go_bool(limits['disable_fast_path'])


def anytls_options(options):
    strict(options, ('password',), ANYTLS_KEYS)
    for key, (low, high) in ANYTLS_INTS.items():
        if key in options:
            budget(options[key], low, high)
    stream = options.get('stream_bytes') or 131072
    if (options.get('session_bytes') or 1048576) < stream:
        reject()
    if 'slow_timeout' in options:
        value = go_duration(options['slow_timeout'])
        if value and not 1000000 <= value <= 60 * NS:
            reject()
    if 'padding_scheme' in options:
        padding_scheme(options['padding_scheme'])


# Kat-Manager single-node kinds and their core inbound protocol names.
KINDS = ('ss', 'anytls', 'trojan', 'socks5')
PROTOCOL = {'ss': 'shadowsocks', 'anytls': 'anytls', 'trojan': 'trojan', 'socks5': 'socks5'}
# SSOptions protection capacities (kernel/encrypted_config.go validate,
# identical in 0.6.0..0.6.2): 0 = core default.
SS_INTS = {'tcp_salts': (0, 1 << 20), 'sessions': (0, 1 << 20), 'salts_2017': (0, 32 * 1024 * 1024)}
SS_RCVBUF_2017 = 1048576
SOCKS5_FIELD_MAX = 255     # kernel: 1..255 bytes for SOCKS5 username/password
TROJAN_PASSWORD_MAX = 4096  # kernel: Trojan password 1..4096 bytes


def ss_options(ss):
    shape(ss, ('method',), ('key', 'password', 'udp_rcvbuf_2017') + tuple(SS_INTS))
    method = text(ss['method'])
    field, other = ('key', 'password') if method.startswith('2022-') else ('password', 'key')
    if field not in ss or other in ss:
        reject()
    for key, (low, high) in SS_INTS.items():
        if key in ss and (type(ss[key]) is not int or not low <= ss[key] <= high):
            reject()
    if 'udp_rcvbuf_2017' in ss:
        value = ss['udp_rcvbuf_2017']
        # 0 = default socket; exactly 1 MiB only on SS2017 listeners.
        if type(value) is not int or value not in (0, SS_RCVBUF_2017) or (value and method.startswith('2022-')):
            reject()
    return method, credential(method, ss[field])


def tls_paths(tls):
    shape(tls, ('cert', 'key'))
    for value in tls.values():
        if not isinstance(value, str) or not SAFE_PATH.fullmatch(value) or '..' in value.split('/'):
            reject()
    return tls


def single_user(users, required):
    # The core accepts up to 1024 users; Kat-Manager manages exactly one node
    # identity (one credential set per protocol), anything else is unsupported.
    if not isinstance(users, list) or len(users) != 1:
        reject()
    strict(users[0], required)
    return users[0]


def node(kind, data, modern=False):
    if modern:
        # Own only the single inbound/identity in 0.7+. The caller must run the
        # real kernel check for all advanced schema and cross references.
        if (not isinstance(data, dict) or any(k.lower() in REMOVED_TOP_KEYS for k in data if isinstance(k, str))
                or not isinstance(data.get('inbounds'), list) or len(data['inbounds']) != 1):
            reject()
        if 'dns' in data:
            if data['dns'] is None:
                reject()
            dns_config(data['dns'])
        inbound = data['inbounds'][0]
        if not isinstance(inbound, dict):
            reject()
        basic = {k: v for k, v in inbound.items() if k in ('protocol', 'listen', 'ss', 'anytls', 'users')}
        if 'tls' in inbound:
            if not isinstance(inbound['tls'], dict):
                reject()
            # Keep the legacy identity reader, not its single-file TLS schema.
            basic['tls'] = {'cert': '/certificate.pem', 'key': '/private.pem'}
        result = node(kind, {'inbounds': [basic]})
        if kind in ('anytls', 'trojan'):
            result['tls'] = inbound.get('tls')
        return result
    if kind not in KINDS:
        reject()
    shape(data, ('inbounds',), ('limits', 'dns'))
    if 'dns' in data:
        if data['dns'] is None:
            reject()
        dns_config(data['dns'])
    if not isinstance(data['inbounds'], list) or len(data['inbounds']) != 1:
        reject()
    # Every core Limits key is recognized with the core's static ranges (a
    # hand-tuned budget does not break view/modify); the manager itself never
    # writes budgets.
    limits_config(data.get('limits', {}))
    inbound = data['inbounds'][0]
    # AnyTLS: an omitted tls means the core's random in-memory certificate; a
    # written tls (including null or {}) must still be the exact cert/key pair.
    # Trojan always has tls; SOCKS5 never (the core has no SOCKS5 TLS wrapper)
    # and must have exactly one username/password user (no anonymous SOCKS5).
    required = {'ss': ('ss',), 'anytls': ('anytls',), 'trojan': ('users', 'tls'), 'socks5': ('users',)}[kind]
    shape(inbound, ('protocol', 'listen') + required, ('tls',) if kind == 'anytls' else ())
    if inbound['protocol'] != PROTOCOL[kind]:
        reject()
    host, p = listen(inbound['listen'])
    result = {'host': host, 'port': p}
    if kind == 'ss':
        method, password = ss_options(inbound['ss'])
        result.update(method=method, password=password)
    elif kind == 'anytls':
        anytls_options(inbound['anytls'])
        if 'tls' in inbound:
            tls_paths(inbound['tls'])
        result.update(password=text(inbound['anytls']['password']), tls=inbound.get('tls'))
    elif kind == 'trojan':
        user = single_user(inbound['users'], ('password',))
        if len(text(user['password']).encode()) > TROJAN_PASSWORD_MAX:
            reject()
        result.update(password=text(user['password']), tls=tls_paths(inbound['tls']))
    else:
        user = single_user(inbound['users'], ('username', 'password'))
        for value in user.values():
            if len(text(value).encode()) > SOCKS5_FIELD_MAX:
                reject()
        result.update(username=user['username'], password=user['password'])
    return result


# Unit markers (comment lines, never systemd semantics):
#   # KatManagerSHA256=<sha256 of /usr/local/bin/kat>   all kinds, exactly once
#   # KatManagerTLS=<policy>                            anytls/trojan, exactly once
#   # KatManagerSNI=<dns name>                          trojan supplied only, exactly once
#   # KatManagerAdopted=<UTC stamp>                     optional, at most once (written by the previous
#                                                       Kat-mode release; still accepted, never written)
MARKERS = ('SHA256', 'TLS', 'SNI', 'Adopted')
# AnyTLS: legacy-insecure = operator-supplied cert/key files (config has tls);
# random-insecure = the core's random in-memory certificate (config omits
# tls). Clients skip verification in both cases.
# Trojan: self-signed = the configured certificate is self-issued (generated
# by Kat-Manager or supplied as such): clients skip verification;
# supplied = a CA-issued certificate: clients verify it for the SNI marker.
TLS_POLICIES = {'anytls': ('legacy-insecure', 'random-insecure'), 'trojan': ('self-signed', 'supplied')}


def markers(raw):
    found = {}
    for line in raw.splitlines():
        if line.startswith('# KatManager'):
            name, sep, value = line[len('# KatManager'):].partition('=')
            if not sep or name not in MARKERS or name in found:
                reject()
            found[name] = value
    return found


def unit(kind, raw):
    binary = unit_body(kind, raw)
    found = markers(raw)
    if not re.fullmatch('[0-9a-f]{64}', found.get('SHA256', '')):
        reject()
    if 'Adopted' in found and not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', found['Adopted']):
        reject()
    if kind in TLS_POLICIES:
        unit_tls_policy(raw, kind)
    elif 'TLS' in found:
        reject()
    unit_sni(kind, raw)
    return binary, found['SHA256']


def unit_body(kind, raw):
    """The service semantics of a Kat unit (ExecStart and the allowed directives), without manager markers."""
    if kind not in KINDS or not isinstance(raw, str) or len(raw.encode()) > MAX_BYTES:
        reject()
    # systemd joins physical lines ending in a backslash. Only the manager's
    # simple, unescaped command form is supported; do not emulate a shell.
    if any(c not in '\n\t' and ord(c) < 32 for c in raw) or any(line.endswith('\\') for line in raw.splitlines()):
        reject()
    lines = raw.split('\n')
    starts = [line[len('ExecStart='):] for line in lines if line.startswith('ExecStart=')]
    if len(starts) != 1:
        reject()
    args = starts[0].split()
    if not re.fullmatch(r'[A-Za-z0-9_./+ \t-]+', starts[0]):
        reject()
    if len(args) != 3 or not SAFE_PATH.fullmatch(args[0]) or '..' in args[0].split('/') or args[1:] != ['run', '/etc/kat/' + kind + '.json']:
        reject()
    # Reject alternate execution/configuration hooks rather than guessing which
    # systemd command is authoritative. Drop-ins are rejected by the collector.
    allowed = {'[Unit]': {'Description', 'After', 'Wants'},
               '[Service]': {'Type', 'User', 'Group', 'ExecStart', 'Restart', 'RestartSec', 'LimitNOFILE'},
               '[Install]': {'WantedBy'}}
    seen = set()
    section = None
    for line in lines:
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            if line not in ('[Unit]', '[Service]', '[Install]'):
                reject()
            section = line
        else:
            key, sep, value = line.partition('=')
            if not sep or key not in allowed.get(section, ()) or key in seen:
                reject()
            seen.add(key)
    return args[0]


def unit_tls_policy(raw, kind='anytls'):
    lines = raw.splitlines()
    found = [policy for policy in TLS_POLICIES[kind] if '# KatManagerTLS=' + policy in lines]
    if len(found) != 1 or lines.count('# KatManagerTLS=' + found[0]) != 1 or markers(raw).get('TLS') != found[0]:
        reject()
    return found[0]


def unit_sni(kind, raw):
    """Trojan supplied-certificate SNI marker; forbidden everywhere else."""
    found = markers(raw)
    if kind == 'trojan' and found.get('TLS') == 'supplied':
        if 'SNI' not in found:
            reject()
        domain_name(found['SNI'])
        if found['SNI'].endswith('.'):
            reject()
        return found['SNI']
    if 'SNI' in found:
        reject()
    return None


def tls_matches(kind, raw_unit, current):
    """AnyTLS: the unit marker and the stored config must name the same certificate source.
    (Trojan's marker is checked against the certificate itself by the manager.)"""
    if kind == 'anytls' and (unit_tls_policy(raw_unit) == 'random-insecure') != (current['tls'] is None):
        reject()

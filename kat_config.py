"""Kat-Manager strict reader: the bounded single-node management contract
for SS / AnyTLS / Trojan / SOCKS5 configurations and kat-<kind>.service units.
Unknown shapes are unsupported, never a signal to install or infer a backend.
"""
import base64
import ipaddress
import json
import re
import shlex
import unicodedata
from urllib.parse import urlsplit

MAX_BYTES = 1 << 20  # the core's configuration size limit
ERROR = 'Kat 配置/单元不完整、不支持或后端冲突；已拒绝自动变更'
METHODS = {'2022-blake3-aes-128-gcm': 16, '2022-blake3-aes-256-gcm': 32,
           '2022-blake3-chacha20-poly1305': 32, 'aes-128-gcm': 0,
           'aes-256-gcm': 0, 'chacha20-ietf-poly1305': 0}
SAFE_PATH = re.compile(r'/[A-Za-z0-9_./+-]+\Z')
# Shared routing core root blocks (frozen 2026-10-24 contract). The manager
# recognizes, validates and preserves them; it never edits or renders them.
CORE_BLOCKS = ('outbounds', 'groups', 'rule_sets', 'geoip')
RESERVED = ('direct', 'reject')
MAX_OUTBOUNDS, MAX_GROUPS, MAX_MEMBERS, MAX_CHAIN, MAX_RULE_SETS = 256, 64, 64, 4, 32
OUTBOUND_TYPES = ('socks5', 'shadowsocks', 'trojan', 'anytls')
OUTBOUND_OPTIONAL = ('via', 'udp', 'username', 'password', 'method', 'key', 'tls', 'idle_sessions', 'idle_timeout')
GROUP_TYPES = ('select', 'url-test', 'fallback', 'smart')
RULE_MATCHERS = ('domain', 'domain_suffix', 'domain_keyword', 'ip_cidr', 'src_ip_cidr',
                 'geoip', 'dst_port', 'network', 'rule_set')
MIB = 1024 * 1024


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


def dns_config(value):
    shape(value, (), ('server', 'cache_entries'))
    server = value.get('server', 'system')
    if not isinstance(server, str) or not server or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in server):
        reject()
    if 'cache_entries' in value:
        cache = value['cache_entries']
        if type(cache) is not int or not 0 <= cache <= 4096 or (server == 'system' and cache != 0):
            reject()
    if server == 'system':
        return
    if any(c in server for c in ('?', '#', '\\')):
        reject()
    if '://' not in server:
        dns_endpoint(server)
        return
    # Use URL parsing only for syntax; no resolution, HTTP or normalization.
    scheme = server.split('://', 1)[0]
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


def strict(value, required, optional=()):
    # New blocks follow the core's strict JSON: no unknown keys, no explicit null.
    shape(value, required, optional)
    if any(item is None for item in value.values()):
        reject()
    return value


# ---------------------------------------------------------------------------
# Routing-core blocks.  Each check below mirrors the candidate core's static
# validation (kernel/outbound_config.go, network_config.go, outbound/*
# Validate, outbound/group.normalize, route.Options.Validate) so that every
# configuration the core accepts is accepted here.  Only facts the core alone
# can know (CA file existence/PEM content) are left to `kat check`.

GO_SPACE = frozenset('\t\n\v\f\r \x85\xa0\u1680\u2028\u2029\u202f\u205f\u3000' + ''.join(map(chr, range(0x2000, 0x200b))))
NS = 1000000000
GO_UNITS = {'ns': 1, 'us': 1000, '\u00b5s': 1000, '\u03bcs': 1000, 'ms': 1000000, 's': NS, 'm': 60 * NS, 'h': 3600 * NS}
HOST_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' "!$&'()*+,;=:[]<>\"-_.~")
USERINFO_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' "-._:~!$&'()*+,;=%@")
HEX_DIGITS = frozenset('0123456789abcdefABCDEF')


def choice(value, allowed):
    if not isinstance(value, str) or value not in allowed:
        reject()
    return value


def string(value, low=1, high=None):
    # Non-empty JSON string (the core rejects "" members); bounds are UTF-8 bytes.
    if not isinstance(value, str) or not low <= len(value.encode()) <= (high or len(value.encode())):
        reject()
    return value


def go_name(value, equals=False):
    """kernel validOutboundName (no '=') / route validName (equals=True)."""
    string(value, 1, 64)
    for c in value:
        if unicodedata.category(c) == 'Cc' or c in GO_SPACE or (c == '=' and not equals):
            reject()
    return value


def go_int(value, low, high):
    if type(value) is not int or not low <= value <= high:
        reject()
    return value


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


def go_ip(value):
    """netip.ParseAddr without zone."""
    if '%' in value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def go_server(value):
    """outbound validServer: zone-less IP literal or LDH(+underscore) name."""
    string(value)
    if go_ip(value):
        return value
    name = value[:-1] if value.endswith('.') else value
    if not name or len(name) > 253:
        reject()
    for label in name.split('.'):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,63}', label) or label[0] == '-' or label[-1] == '-':
            reject()
    return value


def go_clean(path):
    """path/filepath.Clean (Unix)."""
    rooted, parts = path.startswith('/'), []
    for part in path.split('/'):
        if part == '..':
            if parts and parts[-1] != '..':
                parts.pop()
            elif not rooted:
                parts.append('..')
        elif part not in ('', '.'):
            parts.append(part)
    joined = '/'.join(parts)
    return '/' + joined if rooted else joined or '.'


def file_path(value):
    # The core only needs a non-empty NUL-free path; relative paths resolve
    # against the core's working directory. Existence is checked by the core.
    if '\x00' in string(value):
        reject()
    return value


def valid_port(value):
    return value == '' or (value[0] == ':' and all('0' <= c <= '9' for c in value[1:]))


def unescape_ok(data, mode):
    """net/url unescape validity on UTF-8 bytes (modes: host, zone, other)."""
    i = 0
    while i < len(data):
        c = data[i]
        if c == 0x25:
            if i + 2 >= len(data) or chr(data[i + 1]) not in HEX_DIGITS or chr(data[i + 2]) not in HEX_DIGITS:
                return False
            if mode == 'host' and int(chr(data[i + 1]), 16) < 8 and data[i:i + 3] != b'%25':
                return False
            if mode == 'zone':
                v = int(data[i + 1:i + 3], 16)
                if data[i:i + 3] != b'%25' and v != 0x20 and (v >= 0x80 or chr(v) not in HOST_CHARS):
                    return False
            i += 3
            continue
        if mode in ('host', 'zone') and c < 0x80 and chr(c) not in HOST_CHARS:
            return False
        i += 1
    return True


def unescape(text):
    data = re.sub(rb'%([0-9A-Fa-f]{2})', lambda m: bytes([int(m[1], 16)]), text.encode())
    return data.decode('utf-8', 'surrogateescape')


def go_host(host):
    """net/url parseHost (Go 1.26 rules: bracketed hosts must be IPv6; one colon)."""
    if host.startswith('['):
        i = host.rfind(']')
        if i < 0 or not valid_port(host[i + 1:]):
            return None
        zone = host[:i].find('%25')
        if zone >= 0:
            if not (unescape_ok(host[:zone].encode(), 'host') and unescape_ok(host[zone:i].encode(), 'zone')
                    and unescape_ok(host[i:].encode(), 'host')):
                return None
            # address%zone: the zone must be non-empty, the address IPv6.
            literal = unescape(host[1:zone]) + unescape(host[zone:i])
            result = host[:zone] + unescape(host[zone:i]) + host[i:]
        else:
            if not unescape_ok(host.encode(), 'host'):
                return None
            literal = unescape(host[1:i])
            result = unescape(host)
            if '%' in literal:
                return None
        if ':' not in literal.partition('%')[0]:
            return None
        try:
            ipaddress.IPv6Address(literal)
        except ValueError:
            return None
        return result
    i = host.rfind(':')
    if i >= 0 and (':' in host[:i] or not valid_port(host[i:])):
        return None
    return unescape(host) if unescape_ok(host.encode(), 'host') else None


def go_url(value):
    """Subset of Go 1.26 net/url.Parse needed by the core's URL checks."""
    if not isinstance(value, str):
        return None
    head, has_fragment, fragment = value.partition('#')
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in head):
        return None
    scheme, rest = '', head
    for i, c in enumerate(head):
        if c.isascii() and c.isalpha():
            continue
        if c.isascii() and (c.isdigit() or c in '+-.'):
            if i == 0:
                break
            continue
        if c == ':':
            if i == 0:
                return None
            scheme, rest = head[:i].lower(), head[i + 1:]
        break
    if rest.endswith('?') and rest.count('?') == 1:
        rest = rest[:-1]
    else:
        rest = rest.partition('?')[0]
    result = {'scheme': scheme, 'opaque': '', 'user': None, 'host': '', 'fragment': fragment, 'has_fragment': bool(has_fragment)}
    if not rest.startswith('/'):
        result['opaque'] = rest
        return result if scheme else None
    if rest.startswith('//') and (scheme or not rest.startswith('///')):
        authority, slash, path = rest[2:].partition('/')
        rest = slash + path
        at = authority.rfind('@')
        host = go_host(authority[at + 1:])
        if host is None:
            return None
        if at >= 0:
            user = authority[:at]
            if any(c not in USERINFO_CHARS for c in user) or not unescape_ok(user.encode(), 'other'):
                return None
            result['user'] = user
        result['host'] = host
    if not unescape_ok(rest.encode(), 'other') or (has_fragment and not unescape_ok(fragment.encode(), 'other')):
        return None
    return result


def split_host_port(host):
    colon, port = host.rfind(':'), ''
    if colon >= 0 and valid_port(host[colon:]):
        host, port = host[:colon], host[colon + 1:]
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    return host, port


def probe_url(value):
    """group.normalize: absolute http(s) URL; userinfo/query/fragment allowed."""
    string(value)
    url = go_url(value)
    if url is None or url['opaque'] or not url['host'] or url['scheme'] not in ('http', 'https'):
        reject()
    host, port = split_host_port(url['host'])
    address, _, zone = host.partition('%')
    if not host or (zone and ':' in address and go_ip(address)) or (port and not 0 < int(port) <= 65535):
        reject()


def source_url(value):
    """route.validateURL: https only, no userinfo/fragment, at most 2048 bytes."""
    string(value, 1, 2048)
    url = go_url(value)
    if (url is None or url['scheme'] != 'https' or url['opaque'] or url['user'] is not None or not url['host']
            or url['fragment'] or '#' in value):
        reject()
    host, port = split_host_port(url['host'])
    if not host or (port and not 0 < int(port) <= 65535):
        reject()


def ip_prefix(prefix):
    """netip.ParsePrefix: zone-less address, decimal bits without leading zeros."""
    if not isinstance(prefix, str) or '%' in prefix:
        reject()
    address, slash, bits = prefix.rpartition('/')
    if not slash or not re.fullmatch(r'0|[1-9][0-9]*', bits) or not bits.isascii():
        reject()
    if int(bits) > ipaddress.ip_address(address).max_prefixlen:
        reject()


def routing_config(value):
    """Validate routing locally; return (outbound refs, rule_set refs, needs geoip)."""
    strict(value, (), ('rules', 'final'))
    rules = value.get('rules', [])
    if not isinstance(rules, list) or len(rules) > 1024:
        reject()
    refs, sets, geoip = [], [], False
    if 'final' in value:
        refs.append(go_name(value['final'], equals=True))
    for rule in rules:
        if not isinstance(rule, dict):
            reject()
        strict(rule, (), RULE_MATCHERS + ('action', 'outbound', 'no_resolve'))
        selectors = [key for key in RULE_MATCHERS if key in rule]
        actions = [key for key in ('action', 'outbound') if key in rule]
        if len(selectors) != 1 or len(actions) != 1:
            reject()
        selector, action = selectors[0], actions[0]
        match = string(rule[selector])
        if 'no_resolve' in rule and go_bool(rule['no_resolve']) and selector not in ('ip_cidr', 'geoip', 'rule_set'):
            reject()
        if action == 'action':
            choice(rule['action'], RESERVED)
        else:
            # direct/reject written as outbound are the built-ins (core rewrites them).
            refs.append(go_name(rule['outbound'], equals=True))
        if selector in ('ip_cidr', 'src_ip_cidr'):
            ip_prefix(match)
        elif selector in ('domain', 'domain_suffix'):
            domain_name(match)
        elif selector == 'domain_keyword':
            if not re.fullmatch(r'[A-Za-z0-9._-]{1,253}', match):
                reject()
        elif selector == 'geoip':
            private = match.isascii() and match.lower() == 'private'
            if not private and not (len(match) == 2 and match.isascii() and match.isalpha()):
                reject()
            geoip = geoip or not private
        elif selector == 'dst_port':
            ports = re.fullmatch(r'([0-9]{1,5})(?:-([0-9]{1,5}))?', match)
            if not ports or not 1 <= int(ports[1]) <= int(ports[2] or ports[1]) <= 65535:
                reject()
        elif selector == 'network':
            if match.lower() not in ('tcp', 'udp'):
                reject()
        else:
            sets.append(match)
    return refs, sets, geoip


def tls_options(value, trojan):
    strict(value, (), ('server_name', 'ca', 'pin_sha256', 'insecure', 'alpn'))
    if 'server_name' in value:
        # trojan and anytls both validate server_name like server (validServer).
        go_server(value['server_name'])
    if 'ca' in value:
        file_path(value['ca'])
    if 'pin_sha256' in value:
        if not re.fullmatch(r'[0-9a-f]{64}', string(value['pin_sha256']).lower().replace(':', '')):
            reject()
    if 'insecure' in value and go_bool(value['insecure']) and ('pin_sha256' in value or 'ca' in value):
        reject()
    if 'alpn' in value:
        alpn = value['alpn']
        if not isinstance(alpn, list) or len(alpn) > 8:
            reject()
        for protocol in alpn:
            string(protocol, 1, 255)


def outbound_config(value):
    # Credentials are format-checked only; they never enter results or errors.
    kind = choice(value.get('type') if isinstance(value, dict) else None, OUTBOUND_TYPES)
    strict(value, ('name', 'type', 'server', 'port'), OUTBOUND_OPTIONAL)
    go_name(value['name'])
    go_server(value['server'])
    go_int(value['port'], 1, 65535)
    if 'via' in value:
        go_name(value['via'])
    if 'udp' in value:
        go_bool(value['udp'])
    for key in ('username', 'password', 'method', 'key'):
        if key in value:
            string(value[key])
    # Keys that do not apply to a type are accepted only with their zero value.
    sessions = go_int(value.get('idle_sessions', 0), -(1 << 63), (1 << 63) - 1)
    idle = go_duration(value.get('idle_timeout', '0'))
    if 'tls' in value and not isinstance(value['tls'], dict):
        reject()
    if kind != 'anytls' and (sessions or idle):
        reject()
    if kind == 'socks5':
        if 'method' in value or 'key' in value or 'tls' in value or ('username' in value) != ('password' in value):
            reject()
        for key in ('username', 'password'):
            if key in value:
                string(value[key], 1, 255)
        return
    if kind == 'shadowsocks':
        if 'username' in value or 'tls' in value:
            reject()
        size = METHODS[choice(value.get('method'), METHODS)]
        if size:
            key = value.get('key', '')
            if 'password' in value or ':' in key:
                reject()
            key = key.replace('\r', '').replace('\n', '')
            raw = base64.b64decode(key, validate=True)
            if len(raw) != size or base64.b64encode(raw).decode() != key:
                reject()
        elif 'key' in value or not 1 <= len(string(value.get('password')).encode()) <= 4096:
            reject()
        return
    if 'username' in value or 'method' in value or 'key' in value or 'tls' not in value:
        reject()
    string(value.get('password'), 1, 4096)
    if kind == 'anytls' and (not 0 <= sessions <= 32 or not (idle == 0 or NS <= idle <= 600 * NS)):
        reject()
    tls_options(value['tls'], kind == 'trojan')


def group_config(value):
    kind = choice(value.get('type') if isinstance(value, dict) else None, GROUP_TYPES)
    strict(value, ('name', 'type', 'members'), ('selected', 'probe', 'tolerance', 'priority'))
    go_name(value['name'])
    members = value['members']
    if not isinstance(members, list) or not 1 <= len(members) <= MAX_MEMBERS:
        reject()
    for member in members:
        if string(member) == value['name'] or (kind != 'select' and member == 'reject'):
            reject()
    if len(set(members)) != len(members):
        reject()
    if 'selected' in value and (kind != 'select' or value['selected'] not in members):
        reject()
    if 'tolerance' in value:
        tolerance = go_duration(value['tolerance'])
        if tolerance < 0 or (tolerance and kind != 'url-test'):
            reject()
    if 'priority' in value:
        priority = value['priority']
        if not isinstance(priority, dict) or (priority and kind != 'smart'):
            reject()
        for member, weight in priority.items():
            if member not in members or type(weight) not in (int, float) or not 0 < weight <= 100:
                reject()
    if kind == 'select':
        if 'probe' in value:
            reject()
        return
    if 'probe' not in value:
        reject()
    probe = strict(value['probe'], ('url',), ('interval', 'timeout'))
    probe_url(probe['url'])
    interval = go_duration(probe.get('interval', '0'))
    timeout = go_duration(probe.get('timeout', '0'))
    if interval < 0 or 0 < interval < NS or not 0 <= timeout <= 60 * NS:
        reject()


def source_config(value, required, max_bytes, paths):
    # Local file path, optionally refreshed from an explicit https URL.
    strict(value, required + ('path',), ('url', 'interval', 'via', 'max_bytes'))
    clean = go_clean(file_path(value['path']))
    if clean in paths:
        reject()
    paths.add(clean)
    size = go_int(value.get('max_bytes', 0), -(1 << 63), (1 << 63) - 1)
    if size and not 1024 <= size <= max_bytes:
        reject()
    interval = go_duration(value.get('interval', '0'))
    if 'url' not in value:
        if interval or 'via' in value:
            reject()
        return
    source_url(value['url'])
    if interval and interval < 60 * NS:
        reject()
    if 'via' in value and go_name(value['via'], equals=True) == 'reject':
        reject()


def core_config(data, routing_refs):
    """Validate outbounds/groups/rule_sets/geoip and the cross-block graph."""
    lists = {}
    for key, limit in (('outbounds', MAX_OUTBOUNDS), ('groups', MAX_GROUPS), ('rule_sets', MAX_RULE_SETS)):
        lists[key] = data.get(key, [])
        if not isinstance(lists[key], list) or len(lists[key]) > limit:
            reject()
    for value in lists['outbounds']:
        outbound_config(value)
    for value in lists['groups']:
        group_config(value)
    paths = set()
    for value in lists['rule_sets']:
        source_config(value, ('name', 'format'), 64 * MIB, paths)
        go_name(value['name'], equals=True)
        choice(value['format'], ('domain', 'ipcidr', 'classical'))
    sources = list(lists['rule_sets'])
    if 'geoip' in data:
        if not isinstance(data['geoip'], dict):
            reject()
        source_config(data['geoip'], (), 256 * MIB, paths)
        sources.append(data['geoip'])
    outbounds = {value['name']: value for value in lists['outbounds']}
    groups = {value['name']: value for value in lists['groups']}
    if len(outbounds) + len(groups) != len(lists['outbounds']) + len(lists['groups']) or outbounds.keys() & groups.keys():
        reject()
    names = outbounds.keys() | groups.keys()
    if names & set(RESERVED):
        reject()
    # Rule-set names are a separate namespace (they may even be 'direct').
    set_names = [value['name'] for value in lists['rule_sets']]
    if len(set(set_names)) != len(set_names):
        reject()
    refs, set_refs, needs_geoip = routing_refs
    for ref in refs:
        if ref not in names and ref not in RESERVED:
            reject()
    # Country rules need the geoip block; the built-in 'private' does not.
    if not set(set_refs) <= set(set_names) or (needs_geoip and 'geoip' not in data):
        reject()
    for value in [*lists['outbounds'], *sources]:
        # via 'direct' is the explicit default; 'reject' is never a dialer.
        if 'via' in value and value['via'] not in names and value['via'] != 'direct':
            reject()
    for value in lists['groups']:
        if not set(value['members']) <= names | set(RESERVED):
            reject()
    # Dependency graph (via + members) must be acyclic; chain depth counts
    # proxy hops (groups add no hop, direct/reject are depth 0).
    depths, active = {}, set()

    def depth(item):
        if item not in names:
            return 0
        if item in depths:
            return depths[item]
        if item in active:
            reject()
        active.add(item)
        if item in outbounds:
            result = 1 + depth(outbounds[item].get('via', 'direct'))
        else:
            result = max(depth(member) for member in groups[item]['members'])
        active.discard(item)
        if result > MAX_CHAIN:
            reject()
        depths[item] = result
        return result
    for item in sorted(names):
        depth(item)


# Kat core Limits (kernel/config.go) and AnyTLS identity budgets
# (kernel/anytls.go normalize), identical static ranges in 0.6.0..0.6.2; only
# the defaults differ. 0 means "core default". Version-dependent cross-field
# rules (sum of AnyTLS max_streams vs logical_streams) are left to `kat check`.
MAX_DATAGRAM = 65507
LIMIT_INTS = {'logical_streams': (1, 65536), 'connections': (1, 65536), 'handshakes': (1, 65536),
              'dials': (1, 65536), 'udp_associations': (1, 65536), 'pool_buffers': (1, 65536),
              'udp_queue': (1, 256), 'udp_targets': (1, 1024), 'buffer_size': (1024, 65536),
              'udp_queue_bytes': (1, 256 * MAX_DATAGRAM)}
LIMIT_TIMEOUTS = ('handshake_timeout', 'dial_timeout', 'drain_timeout', 'udp_idle')
LIMIT_KEYS = tuple(LIMIT_INTS) + LIMIT_TIMEOUTS + ('tcp_idle', 'disable_fast_path')
ANYTLS_INTS = {'max_sessions': (1, 65536), 'max_streams': (1, 65536), 'session_streams': (1, 64),
               'stream_bytes': (65542, 4 << 20), 'session_bytes': (1, 16 << 20)}
ANYTLS_KEYS = tuple(ANYTLS_INTS) + ('slow_timeout',)


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


def node(kind, data):
    if kind not in KINDS:
        reject()
    shape(data, ('inbounds',), ('limits', 'dns', 'routing') + CORE_BLOCKS)
    if 'dns' in data:
        dns_config(data['dns'])
    routing_refs = routing_config(data['routing']) if 'routing' in data else ([], [], False)
    core_config(data, routing_refs)
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
    lines = raw.splitlines()
    starts = [line[len('ExecStart='):] for line in lines if line.startswith('ExecStart=')]
    if len(starts) != 1:
        reject()
    args = shlex.split(starts[0])
    if len(args) != 3 or not SAFE_PATH.fullmatch(args[0]) or '..' in args[0].split('/') or args[1:] != ['run', '/etc/kat/' + kind + '.json']:
        reject()
    # Reject alternate execution/configuration hooks rather than guessing which
    # systemd command is authoritative. Drop-ins are rejected by the collector.
    allowed = {'Description', 'After', 'Wants', 'Type', 'User', 'Group', 'ExecStart',
               'Restart', 'RestartSec', 'LimitNOFILE', 'WantedBy'}
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
            if not sep or key not in allowed or key in seen or (key == 'ExecStart' and section != '[Service]'):
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

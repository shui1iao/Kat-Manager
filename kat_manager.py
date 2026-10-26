#!/usr/bin/env python3
"""Kat-Manager: one shared Kat core (/usr/local/bin/kat) serving up to four
single-node services kat-ss / kat-anytls / kat-trojan / kat-socks5.

Every mutating action holds /run/lock/kat-manager.lock. Unit markers and
/var/lib/kat-manager/kernel.json are compatible with the earlier
SS-Rust-Manager / AnyTLS-Manager Kat mode; other services (ss-rust, anytls,
...) are never read or touched: an install only has to avoid their ports.
See README.md.
"""
import argparse
import base64
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
from urllib.parse import quote
import urllib.request

from kat_config import (ERROR, KINDS, MAX_BYTES, METHODS, PROTOCOL, SAFE_PATH, credential, domain_name, listen,
                        loads, markers, node, reject, text, tls_matches, unit, unit_sni, unit_tls_policy)

VERSION = '0.1.1'
BIN = '/usr/local/bin/kat'
# Left behind by the previous Kat-mode release; removed after the next successful update.
OLD_ROLLBACK = '/usr/local/bin/kat.rollback'
STATE = '/var/lib/kat-manager'
KERNEL_RECORD = STATE + '/kernel.json'
LOCK = '/run/lock/kat-manager.lock'
LABEL = {'ss': 'SS', 'anytls': 'AnyTLS', 'trojan': 'Trojan', 'socks5': 'SOCKS5'}
ALIASES = {'ss': 'ss', 'shadowsocks': 'ss', 'anytls': 'anytls', 'trojan': 'trojan', 'socks5': 'socks5', 'socks': 'socks5'}
# Only Shadowsocks binds its listen port for UDP too (the core's SOCKS5 UDP
# ASSOCIATE uses an ephemeral port; AnyTLS/Trojan carry UDP inside TCP).
UDP_KINDS = ('ss',)
CERT_DIR = {'anytls': '/etc/kat/anytls', 'trojan': '/etc/kat/trojan'}
SYSTEMD_DIRS = ('/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system')
RELEASE_BASE = 'https://github.com/shui1iao/Kat/releases/download'
RELEASE_LATEST = 'https://api.github.com/repos/shui1iao/Kat/releases/latest'
PUBLIC_IP = 'https://ipv4.icanhazip.com'
PLACEHOLDER = '<服务器IP>'
DEFAULT_METHOD = '2022-blake3-aes-128-gcm'
RANDOM_TLS_MIN = (0, 6, 1)
VERSION_RE = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+')
MAX_DOWNLOAD = 256 << 20
ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
SOCKS5_WARNING = '⚠ 注意：SOCKS5 不加密，流量（包括用户名和密码）在网络上是明文传输！'
PROTOCOL_ACTIONS = ('logs', 'install', 'view', 'config', 'status', 'modify', 'start', 'stop', 'restart', 'uninstall')
GLOBAL_ACTIONS = ('update', 'help', 'menu', 'status')
MUTATING = ('install', 'modify', 'start', 'stop', 'restart', 'update', 'uninstall')
EDIT_FLAGS = ('address', 'port', 'method', 'credential_file', 'username', 'cert', 'key', 'sni',
              'tls_policy', 'ack_certificate_change')
REPOSITORY = 'github.com/shui1iao/Kat-Manager'
AUTHOR = 'shui1iao'
BAR = '=' * 44

USAGE = '''Kat-Manager %s —— Kat 内核统一管理脚本（SS / AnyTLS / Trojan / SOCKS5）

用法：
  bash kat.sh                         交互首页（读 /dev/tty，curl|bash 下也可用）
  bash kat.sh <动作> <协议> [参数]     协议：ss | anytls | trojan | socks5
  bash kat.sh update|status|help [参数]

协议动作：
  install           安装（默认：随机端口、随机凭据、监听 0.0.0.0、内核取 latest）
                    只要端口不冲突就能装；每个协议一个节点，已安装的请用 modify
  view | config     输出节点信息（Surge / Mihomo / URI）
  status            systemd 状态（不带协议时显示总览）
  modify            修改 --port/--listen/--credential-file（SS 可加 --method；SOCKS5 可加 --username）
  start|stop|restart
  logs              查看受管单位 journal（默认最近100行、无分页；--lines N；--follow 才实时）
  uninstall [--purge]  停止并禁用；交互询问是否删除配置/证书/单元（默认保留）
全局动作：
  update [--version X.Y.Z | --binary FILE --sha256 HEX]   更新共享内核（覆盖所有 Kat 服务，失败自动退回）
  status                                                各协议状态总览

参数：
  --version X.Y.Z         Kat 版本（默认 latest）
  --binary FILE --sha256 HEX   离线：使用本地已校验的 Kat 二进制
  --port N | --listen IP:PORT  监听（IPv6 写 [::]:PORT）
  --method M              SS 加密方式（默认 2022-blake3-aes-128-gcm）
  --credential-file F     密码/密钥文件（精确内容，不含换行）；默认随机
  --username NAME         SOCKS5 用户名；默认随机
  --cert F --key F        Trojan 自备证书（AnyTLS 另需 --tls-policy legacy-insecure --ack-certificate-change）
  --sni NAME              Trojan 自备证书时客户端使用的 SNI（默认取证书中的域名）
  --host ADDR             节点输出使用的地址（默认查询公网 IPv4）
  --purge                 uninstall 时不询问，直接删除
''' % VERSION


# ------------------------------------------------------------------ colours
# Same palette and icons as SS-Rust-Manager (YELLOW is magenta there too).
COLORS = {'GREEN': '\033[0;32m', 'RED': '\033[0;31m', 'YELLOW': '\033[0;35m', 'BLUE': '\033[0;34m',
          'CYAN': '\033[0;36m', 'NC': '\033[0m'}


def use_color(stream=None):
    """Colours only on a terminal, and never with NO_COLOR set (no-color.org)."""
    stream = stream or sys.stdout
    try:
        return not os.environ.get('NO_COLOR') and stream.isatty()
    except (AttributeError, ValueError):
        return False


def paint(color, value, stream=None):
    return COLORS[color] + value + COLORS['NC'] if use_color(stream) else value


def ok(message):
    print(paint('GREEN', '✓') + ' ' + message, flush=True)


def info(message):
    print(paint('BLUE', '▶') + ' ' + message, flush=True)


def warn(message, stream=None):
    stream = stream or sys.stdout
    print(paint('YELLOW', '⚠', stream) + ' ' + message, file=stream, flush=True)


def err(message):
    print(paint('RED', '✖', sys.stderr) + ' ' + message, file=sys.stderr, flush=True)


def clear_screen():
    if sys.stdout.isatty():
        sys.stdout.write('\033[H\033[2J')
        sys.stdout.flush()


class Fail(Exception):
    """A fixed, secret-free operator message."""


def fail(message):
    raise Fail(message)


def read(path):
    if path.is_symlink() or not path.is_file() or not path.stat().st_mode & 0o444:
        reject()
    with path.open('rb') as f:
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        reject()
    return data.decode('utf-8')


def trace(path):
    return path.exists() or path.is_symlink()


def write_new(path, data, mode):
    # O_EXCL: existing keys/configs are never silently overwritten on install.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def write_atomic(path, data, mode):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_dir(path, tighten=False, shown=None):
    """A 0700 directory. tighten=True (Kat-Manager state tree only): an existing
    real, root-owned directory with group/other bits (the previous Kat-mode
    release created /var/lib/kat-manager/backups as 0755) is narrowed to 0700."""
    if path.is_symlink():
        reject()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        reject()
    if st.st_mode & 0o077:
        if not tighten or st.st_uid != os.geteuid():
            reject()
        os.chmod(path, 0o700)
        print('提示：已把 ' + (shown or str(path)) + ' 的权限从 ' + oct(st.st_mode & 0o777)[2:].zfill(4) +
              ' 收紧为 0700（上一版遗留）', flush=True)


def file_hash(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def binary_hash(path):
    if not SAFE_PATH.fullmatch(str(path)) or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        reject()
    return file_hash(path)


def kat_version(path):
    try:
        out = subprocess.run([str(path), 'version'], capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.fullmatch(r'kat ([0-9]+\.[0-9]+\.[0-9]+)\s*', out)
    return match[1] if match else None


def version_tuple(value):
    return tuple(int(x) for x in value.split('.')) if value and VERSION_RE.fullmatch(value) else None


# ------------------------------------------------------------ certificates
def certificate(cert, key):
    """Operator/stored cert+key: regular files, a matching pair, not expired."""
    if cert.is_symlink() or key.is_symlink() or not cert.is_file() or not key.is_file():
        reject()
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(cert), str(key))
    if subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '0'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode:
        reject()


def openssl(*args):
    return subprocess.run(['openssl', *args], capture_output=True, text=True, timeout=15)


def cert_mode(cert):
    """'self-signed' for a self-issued leaf (subject == issuer), else 'supplied'."""
    r = openssl('x509', '-in', str(cert), '-noout', '-subject', '-issuer', '-nameopt', 'RFC2253')
    fields = dict(line.split('=', 1) for line in r.stdout.splitlines() if '=' in line)
    if r.returncode or 'subject' not in fields or 'issuer' not in fields:
        reject()
    return 'self-signed' if fields['subject'].strip() == fields['issuer'].strip() else 'supplied'


def cert_covers(cert, name):
    r = openssl('x509', '-in', str(cert), '-noout', '-checkhost', name)
    return r.returncode == 0 and 'does match certificate' in r.stdout


def cert_sni(cert):
    """First non-wildcard DNS name of the certificate (SAN, else CN), or None."""
    r = openssl('x509', '-in', str(cert), '-noout', '-ext', 'subjectAltName')
    names = re.findall(r'DNS:([^,\s]+)', r.stdout) if r.returncode == 0 else []
    if not names:
        s = openssl('x509', '-in', str(cert), '-noout', '-subject', '-nameopt', 'RFC2253')
        match = re.search(r'(?:^subject=|,)CN=([^,]+)', s.stdout.strip())
        names = [match[1]] if match else []
    for name in names:
        try:
            domain_name(name)
        except ValueError:
            continue
        if not name.startswith('*') and not name.endswith('.') and cert_covers(cert, name):
            return name
    return None


def make_self_signed(folder):
    cert, key = folder / 'cert.pem', folder / 'key.pem'
    r = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                        '-days', '3650', '-subj', '/CN=kat-manager', '-keyout', str(key), '-out', str(cert)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=60)
    if r.returncode or not cert.is_file() or not key.is_file():
        fail('openssl 生成自签证书失败；未做任何改动')
    key.chmod(0o600)
    cert.chmod(0o644)
    return cert, key


def random_credential(kind, method=None):
    if kind == 'anytls':
        # Same rule as AnyTLS-Manager rand_pass: 14 alphanumerics + 2 of '-/@', shuffled.
        chars = [secrets.choice(ALNUM) for _ in range(14)] + [secrets.choice('-/@') for _ in range(2)]
        secrets.SystemRandom().shuffle(chars)
        return ''.join(chars)
    if kind in ('trojan', 'socks5'):
        return ''.join(secrets.choice(ALNUM) for _ in range(20))
    if METHODS[method]:
        # openssl rand -base64 N
        return base64.b64encode(secrets.token_bytes(METHODS[method])).decode()
    # openssl rand -base64 18 | tr -d '=+/' | cut -c1-20
    return re.sub('[=+/]', '', base64.b64encode(secrets.token_bytes(18)).decode())[:20]


def random_username():
    return 'kat' + ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(7))


def ask(question):
    """Prompt on the controlling terminal (stdin may be the piped script)."""
    # Text mode 'r+' on a tty raises "not seekable": use an unbuffered fd.
    try:
        fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return None
    try:
        os.write(fd, question.encode())
        data = b''
        while not data.endswith(b'\n'):
            chunk = os.read(fd, 1)
            if not chunk:
                break
            data += chunk
    except OSError:
        return None
    finally:
        os.close(fd)
    if not data:
        return None
    return data.decode('utf-8', 'replace').strip()


def have_tty():
    try:
        os.close(os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY))
        return True
    except OSError:
        return False


def reason(error):
    """A short, secret-free description of an internal failure."""
    if isinstance(error, Fail):
        return str(error)
    if isinstance(error, OSError):
        return '文件或系统调用失败：' + (error.strerror or str(error))[:120]
    return type(error).__name__


def http_get(url, limit, timeout=30):
    request = urllib.request.Request(url, headers={'User-Agent': 'kat-manager', 'Accept': '*/*'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('response too large')
    return data


def width(value):
    return sum(2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in value)


def pad(value, size):
    return value + ' ' * max(0, size - width(value))


class Manager:
    def __init__(self, a):
        self.a = a
        self.kind = a.kind
        root = a.root.resolve()
        if not root.is_absolute() or (root != Path('/') and not a.offline):
            fail('--root 只能与 --offline 一起用于隔离的 staging 目录')
        self.root = root
        self.staging = root != Path('/')
        # Test seams are honoured only for an isolated staging root.
        self.stub = os.environ.get('KAT_MANAGER_TEST_SYSTEMCTL') if self.staging else None
        self.journal_stub = os.environ.get('KAT_MANAGER_TEST_JOURNALCTL') if self.staging else None
        self.settle = float(os.environ.get('KAT_MANAGER_SETTLE_SECONDS', '3'))
        self.keep = []

    def release(self):
        for item in reversed(self.keep):
            if isinstance(item, int):
                os.close(item)
            else:
                item.cleanup()
        self.keep = []

    # ---------------------------------------------------------------- paths
    def t(self, path):
        """Plain staging path (existence checks; system symlinks such as /lib are fine)."""
        return self.root / path.lstrip('/')

    def owned(self, path):
        """A manager-owned path: no symlink below the root (no traversal/redirect)."""
        result = self.t(path)
        for parent in (result, *result.parents):
            if parent == self.root:
                break
            if parent.is_symlink():
                reject()
        return result

    def config(self, kind):
        return self.owned('/etc/kat/' + kind + '.json')

    def service(self, kind):
        return self.owned('/etc/systemd/system/kat-' + kind + '.service')

    def shown(self, path):
        return '/' + str(path.relative_to(self.root)) if self.staging else str(path)

    # -------------------------------------------------------------- systemd
    def ctl(self, *args, check=True):
        command = ['systemctl', *args]
        if self.a.offline:
            print('OFFLINE ' + shlex.join(command), flush=True)
            if not self.stub:
                return True
        result = subprocess.run(([self.stub] if self.stub else ['systemctl']) + list(args), timeout=90)
        if check and result.returncode:
            fail('systemctl ' + ' '.join(args) + ' 执行失败')
        return result.returncode == 0

    def query(self, *args):
        if self.a.offline and not self.stub:
            return None
        try:
            result = subprocess.run(([self.stub] if self.stub else ['systemctl']) + list(args),
                                    capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout.strip()

    def is_active(self, name):
        return self.query('is-active', name)

    def is_enabled(self, name):
        return self.query('is-enabled', name)

    def wait_active(self, name):
        """True when active after settling; None when it cannot be observed (--offline)."""
        if self.a.offline and not self.stub:
            return None
        time.sleep(self.settle)
        deadline = time.monotonic() + 10
        while True:
            state = self.is_active(name)
            if state != 'activating' or time.monotonic() > deadline:
                return state == 'active'
            time.sleep(0.5)

    def unit_state(self, name):
        """(is-enabled, is-active) before a change, for an exact restore."""
        return self.is_enabled(name), self.is_active(name)

    def restore_unit(self, name, state, restart=False):
        """Best effort: bring a unit back to its recorded (enabled, active) state.
        Never raises; returns True when the recorded state is verified/unknown."""
        enabled, active = state
        try:
            self.ctl('daemon-reload', check=False)
            if enabled in ('enabled', None):
                self.ctl('enable', name, check=False)
            elif enabled == 'disabled':
                self.ctl('disable', name, check=False)
            if active in ('active', None):
                current = self.is_active(name)
                if restart or current != 'active':
                    self.ctl('restart', name, check=False)
                return self.wait_active(name) is not False
            self.ctl('stop', name, check=False)
            return True
        except (Fail, OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def describe(state):
        return '/'.join(value or '未知' for value in state)

    def fault(self, point):
        """TEST-ONLY fault injection (staging root only): raise at a named point."""
        if self.staging and point in os.environ.get('KAT_MANAGER_TEST_FAULT', '').split(','):
            raise OSError('injected test fault: ' + point)

    def prepare_state(self):
        """Pre-flight for /var/lib/kat-manager: an existing one must be a real,
        root-owned directory; group/other bits are narrowed to 0700. Nothing is
        created here (a later refusal must leave no trace). Files left there by
        the previous release (migrations/, backups/) are neither read nor changed."""
        for path in (STATE,):
            folder = self.owned(path)
            if trace(folder):
                try:
                    private_dir(folder, tighten=True, shown=path)
                except ValueError:
                    fail(path + ' 不是本机 root 所有的普通目录；请人工检查，未做任何改动')

    def check_private(self, path):
        """Pre-flight for /etc/kat and certificate directories (never auto-changed)."""
        folder = self.owned(path)
        if not trace(folder):
            return
        st = os.lstat(folder)
        if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o077:
            fail(path + ' 必须是权限 0700 的目录（当前 ' + oct(st.st_mode & 0o777)[2:].zfill(4) +
                 '）；请人工确认后 chmod 700，未做任何改动')

    # ----------------------------------------------------------------- lock
    def lock(self):
        path = self.owned(LOCK)
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.keep.append(fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('等待另一个 Kat 管理操作结束（' + LOCK + '）…', file=sys.stderr, flush=True)
            fcntl.flock(fd, fcntl.LOCK_EX)

    # --------------------------------------------------------------- traces
    def kat_traces(self, kind):
        paths = ['/etc/kat/' + kind + '.json']
        if kind in CERT_DIR:
            paths.append(CERT_DIR[kind])
        for directory in SYSTEMD_DIRS:
            paths += [directory + '/kat-' + kind + '.service', directory + '/kat-' + kind + '.service.d']
        return [p for p in paths if trace(self.t(p))]

    def foreign(self, kind):
        """Why existing kat-<kind> files are not this script's installation, else None.
        Such files are shown as 已存在（非本脚本安装） and never touched."""
        traces = self.kat_traces(kind)
        if not traces:
            return None
        vendor = [p for p in traces if p.startswith(('/usr/', '/lib/')) and not p.endswith('.d')]
        if vendor:
            return vendor[0] + ' 不是本脚本写入的单元'
        service = self.t('/etc/systemd/system/kat-' + kind + '.service')
        if not trace(service):
            return '存在 ' + '、'.join(traces) + '，但没有本脚本的 kat-' + kind + '.service'
        try:
            raw = read(service)
        except (ValueError, OSError):
            return None                       # ours or not: shown as 异常
        if not any(line.startswith('# KatManager') for line in raw.splitlines()):
            return 'kat-' + kind + '.service 不是本脚本的格式（没有 KatManager 标记，例如手写的单元）'
        return None

    def refuse_foreign(self, kind):
        why = self.foreign(kind)
        if why:
            fail('Kat ' + LABEL[kind] + ' 已存在（非本脚本安装）：' + why + '；本脚本不接管、不覆盖，未做任何改动')

    # --------------------------------------------------------------- kernel
    def kernel_record(self):
        path = self.owned(KERNEL_RECORD)
        if not trace(path):
            return None
        record = loads(read(path))
        if not isinstance(record, dict) or not VERSION_RE.fullmatch(str(record.get('version'))) or \
                not re.fullmatch('[0-9a-f]{64}', str(record.get('sha256'))):
            fail('内核记录 ' + KERNEL_RECORD + ' 损坏；已拒绝操作')
        return record

    def managed_kernel(self, required=False):
        """The managed core record, None when no core is present; fail on anything else."""
        record = self.kernel_record()
        path = self.owned(BIN)
        if not trace(path):
            if record:
                fail('内核记录存在但 ' + BIN + ' 缺失；请人工检查')
            if required:
                fail('本机没有本脚本安装的 Kat 内核（' + BIN + '）；请先安装一个协议')
            return None
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            fail(BIN + ' 不是可执行的普通文件；请人工检查')
        if record is None:
            fail(BIN + ' 已存在，但不是本脚本安装的（没有 ' + KERNEL_RECORD + '）；为避免影响使用它的服务，'
                 '本脚本不覆盖也不复用它，未做任何改动')
        if file_hash(path) != record['sha256']:
            fail(BIN + ' 的 SHA256 与内核记录不符；请人工检查')
        return record

    def write_kernel_record(self, record):
        private_dir(self.owned(STATE))
        write_atomic(self.owned(KERNEL_RECORD), (json.dumps(record, indent=2) + '\n').encode(), 0o600)

    def arch(self):
        machine = (os.environ.get('KAT_MANAGER_TEST_ARCH') if self.staging else None) or platform.machine()
        if machine not in ('x86_64', 'amd64'):
            fail('Kat 发布件只支持 linux-amd64，当前架构：' + machine + '；未做任何改动')

    def latest(self):
        url = os.environ.get('KAT_RELEASE_LATEST_URL') or RELEASE_LATEST
        try:
            tag = json.loads(http_get(url, 1 << 20).decode()).get('tag_name')
        except (OSError, ValueError, AttributeError, urllib.error.URLError):
            fail('无法获取 Kat 最新版本（' + url + '）；未做任何改动')
        if not isinstance(tag, str) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
            fail('Kat 最新版本标签无效；未做任何改动')
        return tag[1:]

    def scratch(self):
        folder = tempfile.TemporaryDirectory(prefix='kat-manager-')
        self.keep.append(folder)
        return Path(folder.name)

    def fetch(self, version):
        """Download + verify a release asset into a private temp dir. No host change."""
        self.arch()
        version = version or self.latest()
        if not VERSION_RE.fullmatch(version):
            fail('版本号格式应为 X.Y.Z')
        base = (os.environ.get('KAT_RELEASE_BASE_URL') or RELEASE_BASE).rstrip('/')
        asset = 'kat-' + version + '-linux-amd64'
        url = base + '/v' + version + '/' + asset
        info('下载 Kat ' + version + '：' + url)
        try:
            sums = http_get(url + '.sha256', 4096).decode('ascii')
            data = http_get(url, MAX_DOWNLOAD, timeout=300)
        except (OSError, ValueError, urllib.error.URLError):
            fail('下载 Kat ' + version + ' 失败；未做任何改动')
        match = re.fullmatch(r'([0-9a-f]{64})  (\S+)\n?', sums)
        if not match or match[2] != asset:
            fail('.sha256 文件内容或文件名与 ' + asset + ' 不符；未做任何改动')
        if hashlib.sha256(data).hexdigest() != match[1]:
            fail('Kat ' + version + ' SHA256 校验失败；未做任何改动')
        path = self.scratch() / asset
        path.write_bytes(data)
        path.chmod(0o755)
        if kat_version(path) != version:
            fail('下载的二进制报告的版本与 ' + version + ' 不符；未做任何改动')
        info('SHA256 校验通过：' + match[1])
        return path, version, match[1], 'release'

    def local(self, binary, digest, version):
        """--binary/--sha256: an operator-verified local file (offline installs)."""
        self.arch()
        if not digest or not re.fullmatch('[0-9a-f]{64}', digest):
            fail('--binary 需要同时给出 --sha256（64 位小写十六进制）')
        if binary_hash(binary) != digest:
            fail('--binary 的 SHA256 与 --sha256 不符；未做任何改动')
        reported = kat_version(binary)
        if version and reported != version:
            fail('--binary 报告的版本与 --version 不符；未做任何改动')
        path = self.scratch() / 'kat'
        shutil.copyfile(binary, path)
        path.chmod(0o755)
        if file_hash(path) != digest:
            fail('复制本地二进制后校验失败；未做任何改动')
        return path, reported or 'unknown', digest, 'local'

    def candidate(self):
        if self.a.binary:
            return self.local(self.a.binary, self.a.sha256, self.a.version)
        if self.a.sha256:
            fail('--sha256 只能与 --binary 一起使用')
        return self.fetch(self.a.version)

    def place(self, source, digest):
        """Stage a verified file next to /usr/local/bin/kat (same filesystem, for rename)."""
        folder = self.owned('/usr/local/bin')
        folder.mkdir(mode=0o755, parents=True, exist_ok=True)
        staged = folder / ('.kat.new-' + str(os.getpid()))
        try:
            shutil.copyfile(source, staged)
            staged.chmod(0o755)
            if file_hash(staged) != digest:
                fail('写入 ' + BIN + ' 前校验失败')
            return staged
        except BaseException:
            staged.unlink(missing_ok=True)
            raise

    def acquire(self):
        """Core for install: reuse the managed core or fetch one. Returns
        (path for kat check, commit callable, record). Nothing changes before commit."""
        record = self.managed_kernel()
        a = self.a
        if record:
            if a.version and a.version != record['version']:
                fail('本机已有受管 Kat 内核 ' + record['version'] + '，与 --version ' + a.version +
                     ' 不同；请先用 bash kat.sh update --version ' + a.version)
            if a.binary:
                if binary_hash(a.binary) != (a.sha256 or ''):
                    fail('--binary 的 SHA256 与 --sha256 不符；未做任何改动')
                if a.sha256 != record['sha256']:
                    fail('--binary 与已安装的受管内核不同；请用 bash kat.sh update --binary ... --sha256 ...')
            elif a.sha256:
                fail('--sha256 只能与 --binary 一起使用')
            info('复用已安装的 Kat 内核 ' + record['version'] + '（' + BIN + '）')
            return self.owned(BIN), (lambda: False), record
        path, version, digest, source = self.candidate()
        record = {'version': version, 'sha256': digest, 'source': source}

        def commit():
            staged = self.place(path, digest)
            os.replace(staged, self.owned(BIN))
            self.write_kernel_record(record)
            ok('已安装 Kat 内核 ' + version + ' 到 ' + BIN)
            return True
        return path, commit, record

    def make_private(self, path):
        """Create a 0700 directory; returns [topmost directory this call created]
        (missing parents included) so an undo removes exactly that."""
        folder = self.owned(path)
        top = self.first_missing(folder)
        private_dir(folder)
        return [] if top is None else [top]

    @staticmethod
    def first_missing(folder):
        top = None
        while not trace(folder):
            top, folder = folder, folder.parent
        return top

    def undo_created(self, created, fresh, kind):
        """Remove files/directories one change created (reverse order), and the
        core it installed when no other Kat service uses it. Never raises."""
        try:
            if fresh and not self.other_present(kind):
                self.remove_kernel()
        except (OSError, ValueError):
            pass
        unit_written = False
        for path in reversed(created):
            try:
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    unit_written = unit_written or path.name.endswith('.service')
                    path.unlink(missing_ok=True)
            except OSError:
                pass
        if unit_written:
            self.ctl('daemon-reload', check=False)

    def remove_kernel(self):
        for path in (BIN, OLD_ROLLBACK, KERNEL_RECORD):
            self.owned(path).unlink(missing_ok=True)
        # Empty Kat-Manager directories go too (anything else in them stays).
        for path in (STATE, '/etc/kat'):
            try:
                os.rmdir(self.owned(path))
            except OSError:
                pass

    # ------------------------------------------------------------- installs
    def trojan_tls(self, kind, raw_unit, current):
        """Trojan marker vs the configured certificate itself; returns (policy, sni)."""
        if kind != 'trojan':
            return None, None
        policy = unit_tls_policy(raw_unit, 'trojan')
        cert = self.t(current['tls']['cert'])
        if not cert.is_file() or cert_mode(cert) != policy:
            reject()
        sni = unit_sni('trojan', raw_unit)
        if sni and not cert_covers(cert, sni):
            reject()
        return policy, sni

    def managed_unit(self, kind):
        """Ownership without parsing configuration: logs must work even when
        JSON is broken. Fixed ExecStart/config path, markers, hash and drop-in
        checks are still mandatory; no other unit's journal may be selected."""
        traces = self.kat_traces(kind)
        if not traces:
            return None
        self.refuse_foreign(kind)
        if any(p.endswith('.d') for p in traces):
            fail('kat-' + kind + '.service 有 drop-in，实际启动参数无法确定；已拒绝操作')
        self.config(kind)  # reject redirected/symlink config paths, even for logs
        raw_unit = read(self.service(kind))
        binary, digest = unit(kind, raw_unit)
        if binary != BIN:
            fail('kat-' + kind + '.service 的 ExecStart 使用 ' + binary + '，不是 ' + BIN + '；本脚本只管理 ' + BIN)
        path = self.owned(BIN)
        if not path.is_file() or file_hash(path) != digest:
            reject()
        return raw_unit, digest

    def modern(self, binary=None):
        return (version_tuple(kat_version(binary or self.owned(BIN))) or (0,)) >= (0, 7, 0)

    def load(self, kind):
        """A complete managed installation, or None when absent."""
        owned = self.managed_unit(kind)
        if owned is None:
            return None
        raw_unit, digest = owned
        data = loads(read(self.config(kind)))
        modern = self.modern()
        current = node(kind, data, modern=modern)
        if modern:
            self.check(self.owned(BIN), data)
        tls = current.get('tls')
        manual_tls = modern and kind in CERT_DIR and tls is not None and set(tls) != {'cert', 'key'}
        policy, sni = None, None
        if not manual_tls:
            try:
                tls_matches(kind, raw_unit, current)
                policy, sni = self.trojan_tls(kind, raw_unit, current)
            except ValueError:
                if not modern:
                    raise
                # A valid hand-edited TLS source may no longer match the old
                # display policy. Do not rewrite markers or invent client links.
                manual_tls = True
        current = dict(current, policy=policy, sni=sni, tls_manual=manual_tls)
        return {'kind': kind, 'raw_unit': raw_unit, 'data': data, 'current': current, 'digest': digest}

    def installs(self):
        result = {}
        for kind in KINDS:
            try:
                item = self.load(kind)
            except (ValueError, KeyError, TypeError, OSError):
                fail('kat-' + kind + ' 的配置/单元不完整、不受支持或与内核不一致（bash kat.sh status 查看）；未做任何改动')
            if item:
                result[kind] = item
        return result

    def check(self, binary, data, source_tls=False):
        # The temporary check copy lives in /etc/kat when it exists, otherwise in
        # a private temp dir, so a refused install leaves no directory behind.
        folder = self.owned('/etc/kat')
        if not trace(folder):
            folder = self.scratch()
        check(str(binary), data, self.root, folder, source_tls=source_tls, modern=self.modern(binary))

    def unit_text(self, kind, digest, policy=None, sni=None):
        marks = '# KatManagerSHA256=' + digest + '\n'
        if policy:
            marks += '# KatManagerTLS=' + policy + '\n'
        if sni:
            marks += '# KatManagerSNI=' + sni + '\n'
        return (marks + '[Unit]\nDescription=Kat ' + kind +
                '\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nExecStart=' +
                BIN + ' run /etc/kat/' + kind + '.json\nRestart=on-failure\nRestartSec=3\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n')

    def host(self):
        if self.a.host is not None:
            return self.a.host
        url = os.environ.get('KAT_PUBLIC_IP_URL') or PUBLIC_IP
        try:
            value = http_get(url, 256, timeout=8).decode('ascii').strip()
            if ipaddress.ip_address(value).version == 4:
                return value
        except (OSError, ValueError, UnicodeError, urllib.error.URLError):
            pass
        print('未能获取公网 IPv4，节点地址使用占位 ' + PLACEHOLDER + '（可用 --host 指定）', file=sys.stderr, flush=True)
        return PLACEHOLDER

    def build(self, kind, address, password, method=None, username=None):
        inbound = {'protocol': PROTOCOL[kind], 'listen': address}
        data = {'inbounds': [inbound], 'limits': {'tcp_idle': '5m', 'udp_idle': '5m'} if kind == 'ss' else {}}
        if kind == 'ss':
            inbound['ss'] = {'method': method, 'key' if method.startswith('2022-') else 'password': password}
        elif kind == 'anytls':
            inbound['anytls'] = {'password': password}
        elif kind == 'trojan':
            inbound['users'] = [{'password': password}]
            inbound['tls'] = {'cert': CERT_DIR['trojan'] + '/cert.pem', 'key': CERT_DIR['trojan'] + '/key.pem'}
        else:
            inbound['users'] = [{'username': username, 'password': password}]
        return data

    def need_random_tls(self, kind, data, record):
        if kind == 'anytls' and 'tls' not in data['inbounds'][0]:
            have = version_tuple(record.get('version'))
            if have and have < RANDOM_TLS_MIN:
                fail('AnyTLS 随机证书模式需要 Kat ≥ 0.6.1，当前内核 ' + record['version'] +
                     '；请使用 --version 0.6.1 或更高（或先 update）')

    def encode(self, data):
        encoded = (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode()
        if len(encoded) > MAX_BYTES:
            reject()
        return encoded

    # ----------------------------------------------------------------- ports
    def busy_ports(self, udp, exclude=None):
        """{port: owner}: ports of the other Kat configs, TCP listeners and (udp=True)
        bound UDP sockets, read from /proc/net/* (read-only). This is the only
        conflict rule: other services (ss-rust, anytls, ...) only matter here."""
        ports = {}
        for kind in KINDS:
            if kind == exclude:
                continue
            try:
                ports[listen(loads(read(self.t('/etc/kat/' + kind + '.json')))['inbounds'][0]['listen'])[1]] = \
                    'Kat ' + LABEL[kind] + ' 的配置 /etc/kat/' + kind + '.json'
            except (ValueError, KeyError, TypeError, IndexError, OSError):
                pass
        for name in ('tcp', 'tcp6') + (('udp', 'udp6') if udp else ()):
            try:
                lines = self.t('/proc/net/' + name).read_text().splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) > 3 and (name.startswith('udp') or fields[3] == '0A'):
                    try:
                        ports.setdefault(int(fields[1].rsplit(':', 1)[1], 16),
                                         '已有进程监听 ' + ('UDP' if name.startswith('udp') else 'TCP'))
                    except (ValueError, IndexError):
                        pass
        return ports

    def free_port(self, port, kind, exclude=None):
        owner = self.busy_ports(kind in UDP_KINDS, exclude).get(port)
        if owner:
            fail('端口 ' + str(port) + ' 已被占用（' + owner + '）；请换一个端口，未做任何改动')

    def random_port(self):
        # 10000..65535 like SS-Rust-Manager / AnyTLS-Manager, avoiding every busy
        # TCP/UDP port and every other Kat config's port.
        busy = self.busy_ports(True)
        free = [port for port in range(10000, 65536) if port not in busy]
        if not free:
            fail('10000-65535 之间找不到空闲端口；请用 --port 指定')
        return secrets.choice(free)

    # ---------------------------------------------------------------- actions
    def run(self):
        a = self.a
        if os.geteuid() != 0:
            fail('请用 root 运行')
        try:
            if a.action in MUTATING:
                self.lock()
            handler = getattr(self, 'do_' + a.action.replace('-', '_'))
            return handler()
        finally:
            self.release()

    def no_edit_flags(self):
        a = self.a
        if any(getattr(a, flag) for flag in EDIT_FLAGS):
            fail('该动作不接受修改类参数')

    def no_kernel_flags(self):
        if self.a.binary or self.a.sha256 or self.a.version:
            fail('该动作不接受 --version/--binary/--sha256')

    def installed(self):
        item = self.load(self.kind)
        if not item:
            fail('未安装 Kat ' + LABEL[self.kind] + '（未找到 /etc/kat/' + self.kind + '.json 与 kat-' + self.kind + '.service）')
        return item

    def credential_input(self):
        a = self.a
        if a.credential_file:
            return read(a.credential_file)
        return getattr(a, 'credential', None)

    def do_view(self):
        self.no_edit_flags()
        self.no_kernel_flags()
        item = self.installed()
        self.check(self.owned(BIN), item['data'])
        display(self.kind, self.host(), item['current'])

    do_config = do_view

    def do_logs(self):
        self.no_edit_flags()
        self.no_kernel_flags()
        if self.managed_unit(self.kind) is None:
            fail('未安装 Kat ' + LABEL[self.kind] + '；没有可定位的受管单位')
        args = ['--unit', 'kat-' + self.kind + '.service', '--lines', str(self.a.lines or 100), '--no-pager']
        if self.a.follow:
            args.append('--follow')
        if self.a.offline:
            print('OFFLINE ' + shlex.join(['journalctl', *args]), flush=True)
            if not self.journal_stub:
                return  # never read the host journal during staging/offline tests
        try:
            result = subprocess.run(([self.journal_stub] if self.journal_stub else ['journalctl']) + args,
                                    timeout=None if self.a.follow else 30)
        except KeyboardInterrupt:
            info('已停止查看日志')
            return
        if result.returncode:
            fail('journalctl 查看受管单位日志失败；未修改配置或服务')

    def do_status(self):
        self.no_edit_flags()
        self.no_kernel_flags()
        if self.kind is None:
            self.overview()
            return
        item = self.installed()
        self.check(self.owned(BIN), item['data'])
        self.ctl('--no-pager', '--full', 'status', 'kat-' + self.kind + '.service', check=False)

    def do_start(self):
        self.service_action('start')

    def do_stop(self):
        self.service_action('stop')

    def do_restart(self):
        self.service_action('restart')

    def service_action(self, action):
        # Credentials/certificate changes cannot hitchhike on a service action.
        self.no_edit_flags()
        self.no_kernel_flags()
        item = self.installed()
        self.check(self.owned(BIN), item['data'])
        name = 'kat-' + self.kind + '.service'
        self.ctl(action, name)
        if action != 'stop' and self.wait_active(name) is False:
            fail(name + ' 未能进入 active；请查看 journalctl -u ' + name)
        ok(name + ' ' + {'start': '已启动', 'stop': '已停止', 'restart': '已重启'}[action])

    def option_kinds(self):
        """Per-protocol flags; anything else is refused before any change."""
        a, kind = self.a, self.kind
        if a.method and kind != 'ss':
            fail('--method 只适用于 ss')
        if a.username and kind != 'socks5':
            fail('--username 只适用于 socks5')
        if (a.cert or a.key) and kind not in ('anytls', 'trojan'):
            fail('--cert/--key 只适用于 anytls、trojan')
        if (a.tls_policy or a.ack_certificate_change) and kind != 'anytls':
            fail('--tls-policy/--ack-certificate-change 只适用于 anytls')
        if a.sni and kind != 'trojan':
            fail('--sni 只适用于 trojan')

    def do_install(self):
        a, kind = self.a, self.kind
        self.option_kinds()
        # One node per protocol: an existing installation is never overwritten.
        try:
            existing = self.load(kind)
        except (ValueError, KeyError, TypeError, OSError):
            fail('Kat ' + LABEL[kind] + ' 已存在但配置/单元异常（bash kat.sh status 查看）；不会覆盖，未做任何改动')
        if existing:
            fail('Kat ' + LABEL[kind] + ' 已安装（端口 ' + str(existing['current']['port']) + '），可在管理协议里修改'
                 '（bash kat.sh modify ' + kind + ' …）；不会覆盖，未做任何改动')
        if a.address and a.port:
            fail('--listen 与 --port 只能给一个')
        method = a.method
        username = None
        if a.address or a.port:
            address = a.address or '0.0.0.0:' + str(a.port)
            try:
                listen(address)
            except ValueError:
                fail('--listen 格式应为 IP:端口（IPv6 写 [::]:端口）')
            self.free_port(listen(address)[1], kind)
        else:
            address = '0.0.0.0:' + str(self.random_port())
        if kind == 'ss':
            method = method or DEFAULT_METHOD
            if method not in METHODS:
                fail('不支持的 SS 加密方式：' + method + '（可选：' + ' '.join(METHODS) + '）')
        password = self.credential_input()
        if password is None:
            password = random_credential(kind, method)
        if kind == 'socks5':
            username = a.username or random_username()
        if kind == 'socks5':
            self.socks5_user(username, password)
        try:
            if kind == 'ss':
                credential(method, password)
            else:
                text(password)
        except ValueError:
            fail('凭据不合法（不能为空、不能含控制字符；SS2022 需要对应长度的 Base64 密钥）；未做任何改动')
        source_tls = None          # (cert, key) checked from their source location
        policy, sni = None, None
        if kind == 'anytls':
            if a.cert or a.key:
                # Operator-supplied files: unchanged checks, policy and gate.
                if not a.cert or not a.key or a.tls_policy != 'legacy-insecure' or not a.ack_certificate_change:
                    fail('AnyTLS 自备证书需要同时给出 --cert --key --tls-policy legacy-insecure --ack-certificate-change')
                certificate(a.cert, a.key)
                source_tls = (a.cert, a.key)
                policy = 'legacy-insecure'
            elif a.tls_policy or a.ack_certificate_change:
                fail('--tls-policy/--ack-certificate-change 需要与 --cert/--key 一起使用')
            else:
                policy = 'random-insecure'
        elif kind == 'trojan':
            if a.cert or a.key:
                if not a.cert or not a.key:
                    fail('Trojan 自备证书需要同时给出 --cert 和 --key')
                try:
                    certificate(a.cert, a.key)
                except (ValueError, ssl.SSLError, OSError):
                    fail('--cert/--key 不是配对、有效且未过期的证书和私钥；未做任何改动')
                source_tls = (a.cert, a.key)
                policy = cert_mode(a.cert)
                if policy == 'supplied':
                    sni = a.sni or cert_sni(a.cert)
                    if not sni:
                        fail('无法从证书中取得域名；请用 --sni 指定客户端使用的域名')
                    self.valid_sni(a.cert, sni)
                else:
                    if a.sni:
                        fail('该证书是自签名证书，客户端会跳过校验，不使用 --sni')
                    info('提示：--cert 是自签名证书，按自签模式处理（客户端跳过证书校验）')
            else:
                if a.sni:
                    fail('--sni 只用于 --cert/--key 自备证书')
                source_tls = make_self_signed(self.scratch())
                policy = 'self-signed'
        data = self.build(kind, address, password, method, username)
        if kind == 'anytls' and source_tls:
            data['inbounds'][0]['tls'] = {'cert': CERT_DIR['anytls'] + '/cert.pem', 'key': CERT_DIR['anytls'] + '/key.pem'}
        final = dict(node(kind, data), policy=policy if kind == 'trojan' else None, sni=sni)
        encoded = self.encode(data)
        binary, commit, record = self.acquire()
        self.need_random_tls(kind, data, record)
        check_data = copy.deepcopy(data)
        if source_tls:
            check_data['inbounds'][0]['tls'] = {'cert': str(source_tls[0]), 'key': str(source_tls[1])}
        try:
            self.check(binary, check_data, source_tls=bool(source_tls))
        except ValueError:
            fail('新配置未通过 kat check；未做任何改动')
        raw_unit = self.unit_text(kind, record['sha256'], policy if kind in CERT_DIR else None, sni)
        unit(kind, raw_unit)
        # Pre-flight (nothing changed yet): directory permissions.
        self.check_private('/etc/kat')
        self.prepare_state()
        top = self.first_missing(self.owned(STATE))
        fresh, created = False, [] if top is None else [top]
        try:
            fresh = commit()
            created += self.make_private('/etc/kat')
            if source_tls:
                created += self.make_private(CERT_DIR[kind])
                folder = self.owned(CERT_DIR[kind])
                write_new(folder / 'key.pem', Path(source_tls[1]).read_bytes(), 0o600)
                write_new(folder / 'cert.pem', Path(source_tls[0]).read_bytes(), 0o644)
            self.service(kind).parent.mkdir(parents=True, exist_ok=True)
            write_new(self.config(kind), encoded, 0o600)
            created.append(self.config(kind))
            self.fault('install-write-unit')
            write_new(self.service(kind), raw_unit.encode(), 0o644)
            created.append(self.service(kind))
            self.ctl('daemon-reload')
        except BaseException as e:
            # No service was touched: remove exactly what this install created.
            self.undo_created(created, fresh, kind)
            if isinstance(e, (Fail, OSError, ValueError, subprocess.SubprocessError)):
                fail('安装 kat-' + kind + ' 未完成（' + reason(e) + '）；已清理本次写入的文件' +
                     ('和内核' if fresh else '') + '，其他服务未受影响')
            raise
        try:
            self.ctl('enable', '--now', 'kat-' + kind + '.service')
            started = self.wait_active('kat-' + kind + '.service')
        except Fail:
            started = False
        if started is False:
            err('kat-' + kind + '.service 未能进入 active；配置已写入，请查看 journalctl -u kat-' + kind +
                '.service（例如端口被占用时可 bash kat.sh modify ' + kind + ' --port N）')
            display(kind, self.host(), final)
            sys.exit(1)
        ok('已安装并启动 kat-' + kind + '.service')
        display(kind, self.host(), final)

    def valid_sni(self, cert, sni):
        try:
            domain_name(sni)
            if sni.endswith('.') or sni.startswith('*'):
                reject()
        except ValueError:
            fail('--sni 必须是域名；未做任何改动')
        if not cert_covers(cert, sni):
            fail('证书不包含域名 ' + sni + '；未做任何改动')

    def socks5_user(self, username, password):
        try:
            for value in (username, password):
                if len(text(value).encode()) > 255:
                    reject()
        except ValueError:
            fail('SOCKS5 必须设置用户名和密码（各 1-255 字节，不能含控制字符）；不支持无认证，未做任何改动')

    def do_modify(self):
        a, kind = self.a, self.kind
        self.no_kernel_flags()
        self.option_kinds()
        if a.cert or a.key or a.sni or a.tls_policy or a.ack_certificate_change:
            fail('modify 不支持更换证书；请卸载后重新安装')
        if a.address and a.port:
            fail('--listen 与 --port 只能给一个')
        new_credential = self.credential_input()
        if not any((a.address, a.port, a.method, new_credential is not None, a.username)):
            fail('modify 需要至少一个修改项：--port / --listen / --credential-file' +
                 (' / --method' if kind == 'ss' else '') + (' / --username' if kind == 'socks5' else ''))
        item = self.installed()
        data = copy.deepcopy(item['data'])
        current = item['current']
        inbound = data['inbounds'][0]
        if a.address:
            inbound['listen'] = a.address
        elif a.port:
            host = current['host']
            inbound['listen'] = ('[' + host + ']' if ':' in host else host) + ':' + str(a.port)
        try:
            new_port = listen(inbound['listen'])[1]
        except ValueError:
            fail('--listen 格式应为 IP:端口（IPv6 写 [::]:端口）')
        if new_port != current['port']:
            self.free_port(new_port, kind, exclude=kind)
        if kind == 'ss':
            old = inbound['ss']
            method = a.method or old['method']
            if method not in METHODS:
                fail('不支持的 SS 加密方式：' + method)
            if method != old['method'] and new_credential is None:
                fail('更换 SS 加密方式时必须同时用 --credential-file 给出新密钥/密码')
            password = new_credential if new_credential is not None else current['password']
            extra = {k: v for k, v in old.items() if k not in ('method', 'key', 'password')}
            inbound['ss'] = dict({'method': method, 'key' if method.startswith('2022-') else 'password': password}, **extra)
        elif new_credential is not None:
            if kind == 'anytls':
                inbound['anytls']['password'] = new_credential
            else:
                inbound['users'][0]['password'] = new_credential
        if kind == 'socks5':
            if a.username:
                inbound['users'][0]['username'] = a.username
            self.socks5_user(inbound['users'][0]['username'], inbound['users'][0]['password'])
        try:
            final = dict(node(kind, data, modern=self.modern()), policy=current.get('policy'),
                         sni=current.get('sni'), tls_manual=current.get('tls_manual', False))
        except ValueError:
            fail('新的监听或凭据不合法；未做任何改动')
        encoded = self.encode(data)
        try:
            self.check(self.owned(BIN), data)
        except ValueError:
            fail('新配置未通过 kat check；未做任何改动')
        name = 'kat-' + kind + '.service'
        config = self.config(kind)
        old_bytes = config.read_bytes()
        old_mode = config.stat().st_mode & 0o777
        before = self.unit_state(name)
        state = before[1]
        # The atomic write is the last step that can fail before the service is touched.
        self.fault('modify-write-config')
        write_atomic(config, encoded, 0o600)
        if state not in ('active', None):
            ok('配置已更新；' + name + ' 当前未运行（' + str(state) + '），下次启动时生效')
            display(kind, self.host(), final)
            return
        try:
            self.fault('modify-after-write')
            self.ctl('restart', name)
            started = self.wait_active(name)
        except (Fail, OSError, subprocess.SubprocessError):
            started = False
        if started is not False:
            ok('配置已更新，' + name + ' 已重启')
            display(kind, self.host(), final)
            return
        # The new configuration does not run: put the old one back and restart it.
        try:
            write_atomic(config, old_bytes, old_mode)
            restored = 'restored'
        except OSError:
            restored = 'not-restored'
        back = self.restore_unit(name, before, restart=True) if restored == 'restored' else False
        err(name + ' 用新配置未能启动；' + ('已恢复原配置并重启，' + ('服务已恢复运行' if back else '但服务仍未运行，请查看 journalctl -u ' + name)
                                       if restored == 'restored' else '原配置写回失败，请人工检查 /etc/kat/' + kind + '.json') +
            '。修改未生效')
        sys.exit(1)

    # ------------------------------------------------------------ update
    def swap_units(self, items, digest):
        for kind, item in items.items():
            raw = re.sub(r'^# KatManagerSHA256=[0-9a-f]{64}$', '# KatManagerSHA256=' + digest, item['raw_unit'],
                         count=1, flags=re.M)
            unit(kind, raw)
            path = self.service(kind)
            write_atomic(path, raw.encode(), path.stat().st_mode & 0o777)

    def restart_running(self, items, running, attempted=None):
        self.ctl('daemon-reload')
        failed = []
        for kind in items:
            name = 'kat-' + kind + '.service'
            if running.get(kind) in ('active', None):
                if attempted is not None:
                    attempted.append(name)
                self.ctl('restart', name, check=False)
                if self.wait_active(name) is False:
                    failed.append(name)
        return failed

    def preflight(self, binary, items, label):
        for kind, item in items.items():
            try:
                self.check(binary, item['data'])
            except ValueError:
                fail(label + ' 对 /etc/kat/' + kind + '.json 执行 kat check 未通过；未做任何改动')

    def do_update(self):
        self.no_edit_flags()
        record = self.managed_kernel(required=True)
        items = self.installs()
        self.prepare_state()
        a = self.a
        if a.binary and a.sha256 == record['sha256']:
            ok('当前内核已是该二进制（' + record['version'] + '），未做任何改动')
            return
        if not a.binary:
            if a.sha256:
                fail('--sha256 只能与 --binary 一起使用')
            self.arch()
            requested = a.version
            version = requested or self.latest()
            if version == record['version'] and record.get('source') != 'local':
                ok(('当前内核已是 ' + version if requested else '已是最新版本（' + version + '）') + '，未做任何改动')
                return
            a.version = version
        path, version, digest, source = self.candidate()
        if digest == record['sha256']:
            ok('当前内核已是 ' + version + '，未做任何改动')
            return
        self.preflight(path, items, '新内核 ' + version)
        new = {'version': version, 'sha256': digest, 'source': source}
        self.exchange(items, record, new, self.place(path, digest))

    def exchange(self, items, old, new, staged):
        """Keep the current core as a private hard link, rename the staged core
        over /usr/local/bin/kat (atomic), refresh every unit hash, restart the
        running services. Any failure after the swap restores core, units,
        record and running state. Success deletes the old core: no rollback
        copy is kept (a kat.rollback left by the previous release goes too)."""
        current = self.owned(BIN)
        hold = self.owned('/usr/local/bin/.kat.old-' + str(os.getpid()))
        running = {kind: self.is_active('kat-' + kind + '.service') for kind in items}
        record_path = self.owned(KERNEL_RECORD)
        old_record = record_path.read_bytes()
        try:
            os.link(current, hold)
            os.replace(staged, current)
        except BaseException:
            staged.unlink(missing_ok=True)
            if trace(hold) and trace(current) and os.path.samefile(hold, current):
                hold.unlink()
            raise
        failed, error, attempted = [], None, []
        try:
            self.fault('exchange-units')
            self.swap_units(items, new['sha256'])
            self.fault('exchange-record')
            self.write_kernel_record(new)
            failed = self.restart_running(items, running, attempted)
        except (Fail, OSError, ValueError, subprocess.SubprocessError) as e:
            error = e
        if not failed and error is None:
            hold.unlink(missing_ok=True)
            cleaned = False
            try:
                if trace(self.owned(OLD_ROLLBACK)):
                    self.owned(OLD_ROLLBACK).unlink()
                    cleaned = True
            except (OSError, ValueError):
                pass
            ok('Kat 内核更新完成：' + old['version'] + ' -> ' + new['version'] + '（不保留旧版本）')
            if cleaned:
                info('已清理上一版遗留的 ' + OLD_ROLLBACK)
            for kind in items:
                info('已刷新 kat-' + kind + '.service 的 KatManagerSHA256' +
                     ('，并已重启' if running.get(kind) in ('active', None) else '（服务未运行，未重启）'))
            return
        # Automatic revert to the core kept at the private hard link.
        problems = []
        try:
            os.replace(hold, current)
        except OSError:
            problems.append('内核文件')
        for kind, item in items.items():
            try:
                path = self.service(kind)
                write_atomic(path, item['raw_unit'].encode(), path.stat().st_mode & 0o777)
            except OSError:
                problems.append('kat-' + kind + '.service')
        try:
            write_atomic(record_path, old_record, 0o600)
        except OSError:
            problems.append(KERNEL_RECORD)
        try:
            if attempted:
                again = self.restart_running(items, running)
            else:
                # No service was restarted: they still run the old core.
                self.ctl('daemon-reload', check=False)
                again = [name for name in ('kat-' + kind + '.service' for kind in items)
                         if running.get(name[4:-8]) == 'active' and self.is_active(name) != 'active']
        except (Fail, OSError, subprocess.SubprocessError):
            again = ['systemctl']
        cause = ('服务未能启动（' + ', '.join(failed) + '）') if failed else ('步骤失败（' + reason(error) + '）')
        err('Kat 内核更新时' + cause + '；已自动回到 ' + old['version'] +
            ('' if not problems else '，但以下项目未能恢复，请人工检查：' + '、'.join(problems)) +
            ('，恢复后的服务状态正常' if not again else '，但恢复后仍未运行：' + ', '.join(again)))
        sys.exit(1)

    # --------------------------------------------------------------- uninstall
    def other_present(self, kind):
        return any(self.kat_traces(other) for other in KINDS if other != kind)

    def do_uninstall(self):
        self.no_edit_flags()
        self.no_kernel_flags()
        kind = self.kind
        if not self.kat_traces(kind):
            fail('未安装 Kat ' + LABEL[kind])
        self.refuse_foreign(kind)
        if any(p.endswith('.d') for p in self.kat_traces(kind)):
            fail('kat-' + kind + '.service 有 drop-in；不支持，已拒绝操作')
        name = 'kat-' + kind + '.service'
        present = trace(self.service(kind))
        # Pre-flight, before the service is touched: the decision and the
        # private stash directory a purge needs.
        if self.a.purge:
            purge = True
        else:
            answer = ask('是否删除 Kat ' + LABEL[kind] + ' 的配置、证书和单元文件？[y/N]: ')
            purge = bool(answer) and answer.lower() in ('y', 'yes')
            if answer is None:
                info('非交互环境且未给 --purge：保留配置、证书和单元文件')
        folder = None
        if purge:
            for path, _ in self.stash_items(kind):
                self.owned(path)
            self.prepare_state()
            folder = self.stash_dir(kind)
        before = self.unit_state(name) if present else None
        try:
            if present:
                self.ctl('disable', '--now', name)
            if purge:
                self.fault('uninstall-stash')
                self.stash_into(kind, folder)
                self.ctl('daemon-reload')
        except (Fail, OSError, ValueError, subprocess.SubprocessError) as e:
            restored_files = self.unstash(kind, folder) if folder else True
            back = self.restore_unit(name, before) if present else True
            files = '配置、证书和单元已放回原处' if restored_files else '部分文件未能放回，见 ' + self.shown(folder)
            if not present:
                service = ''
            elif back:
                service = '，' + name + ' 已恢复为 ' + self.describe(before)
            else:
                service = '，' + name + ' 未能恢复原状态（原为 ' + self.describe(before) + '），请人工检查'
            err('卸载 Kat ' + LABEL[kind] + ' 失败（' + reason(e) + '）；' + files + service)
            sys.exit(1)
        if not purge:
            ok('已停止并禁用 ' + name + '；配置、证书和单元文件均已保留')
            info('保留 ' + BIN + '（只有删除文件且其他 Kat 服务都不存在时才删除内核）')
            return
        # The service is gone on purpose; what is left is cleanup of the stash.
        shutil.rmtree(folder, ignore_errors=True)
        ok('已停止并删除 Kat ' + LABEL[kind] + ' 的配置、证书和单元文件')
        others = [k for k in KINDS if k != kind and self.kat_traces(k)]
        if others:
            info('其他 Kat 服务（' + '、'.join('kat-' + k for k in others) + '）仍在使用 ' + BIN + '，保留内核')
            return
        try:
            self.remove_kernel()
        except (OSError, ValueError) as e:
            fail('kat-' + kind + ' 已删除，但删除内核时失败（' + reason(e) + '）；请人工检查 ' + BIN)
        ok('已删除 ' + BIN + ' 和内核记录')

    def stash_dir(self, kind):
        """Private holding place for a purge (restored if the purge fails)."""
        folder = self.owned(STATE + '/.uninstall-' + kind + '-' + str(os.getpid()))
        private_dir(self.owned(STATE), tighten=True, shown=STATE)
        private_dir(folder)
        return folder

    def stash_items(self, kind):
        items = [('/etc/kat/' + kind + '.json', kind + '.json'),
                 ('/etc/systemd/system/kat-' + kind + '.service', 'kat-' + kind + '.service')]
        if kind in CERT_DIR:
            items.append((CERT_DIR[kind], kind + '-certificates'))
        return items

    def stash_into(self, kind, folder):
        """Move Kat config/unit/certificates into the stash."""
        self.fault('stash-move')
        for path, name in self.stash_items(kind):
            if trace(self.owned(path)):
                shutil.move(str(self.owned(path)), str(folder / name))

    def unstash(self, kind, folder):
        """Move stashed files back; drop the then-empty stash. True when complete."""
        complete = True
        for path, name in self.stash_items(kind):
            if trace(folder / name):
                try:
                    shutil.move(str(folder / name), str(self.owned(path)))
                except (OSError, ValueError):
                    complete = False
        try:
            folder.rmdir()
        except OSError:
            pass
        return complete

    # ------------------------------------------------------------- home page
    def diagnose(self, kind, error):
        if isinstance(error, Fail):
            return str(error)
        service, config = self.t('/etc/systemd/system/kat-' + kind + '.service'), self.t('/etc/kat/' + kind + '.json')
        if not trace(config):
            return '有单元文件但缺少 /etc/kat/' + kind + '.json'
        try:
            raw = read(service)
            found = markers(raw)
            if trace(self.t(BIN)) and found.get('SHA256') != file_hash(self.t(BIN)):
                return '单元的 KatManagerSHA256 与 ' + BIN + ' 不符'
        except (ValueError, OSError):
            return 'KatManager 标记重复或无效'
        return '配置/单元/证书不完整或不一致'

    def probe(self, kind):
        """(state, detail) for the home page; never raises. States: 未安装 / 运行中 /
        已停止 / 已存在（非本脚本安装） / 异常."""
        try:
            if not self.kat_traces(kind):
                return '未安装', ''
            why = self.foreign(kind)
            if why:
                return '已存在（非本脚本安装）', why
            try:
                item = self.load(kind)
            except (ValueError, KeyError, TypeError, OSError, Fail) as e:
                return '异常', self.diagnose(kind, e)
            port = '端口 ' + str(item['current']['port'])
            state = self.is_active('kat-' + kind + '.service')
            if state == 'active':
                return '运行中', port
            if state in ('inactive', 'failed'):
                return '已停止', port + ('（上次运行失败）' if state == 'failed' else '')
            if state in ('activating', 'deactivating', 'reloading'):
                return '异常', 'systemd 状态 ' + state + '，' + port
            return '异常', '无法获取 systemd 状态，' + port
        except (ValueError, KeyError, TypeError, OSError, Fail) as e:
            return '异常', str(e) if isinstance(e, Fail) else '无法读取或判定'

    def kernel_line(self):
        try:
            record = self.managed_kernel()
        except (Fail, ValueError, OSError) as e:
            path = self.t(BIN)
            if path.is_file() and not trace(self.t(KERNEL_RECORD)):
                return paint('RED', (kat_version(path) or '版本未知') + '（非本脚本安装）')
            return paint('RED', '异常：' + (str(e) if isinstance(e, Fail) else '内核记录无法读取'))
        if record is None:
            return paint('RED', '未安装')
        return record['version']

    def status_line(self, kind):
        state, detail = self.probe(kind)
        color = {'运行中': 'GREEN', '已停止': 'RED', '未安装': 'YELLOW'}.get(state, 'RED')
        if color == 'RED' and state != '已停止':
            text_ = paint('RED', state + '：' + detail)
        else:
            text_ = paint(color, state) + ('  ' + detail if detail else '')
        return pad(LABEL[kind], 7) + '：' + text_

    def overview(self, menu=False):
        """The home page header and status block (also `kat.sh status`)."""
        print(paint('CYAN', BAR))
        print(' ' * 10 + paint('CYAN', 'Kat 管理脚本 v' + VERSION))
        print(paint('CYAN', BAR))
        print(paint('GREEN', '仓库: ' + REPOSITORY))
        print(paint('GREEN', '作者: ' + AUTHOR))
        print(paint('CYAN', BAR))
        print('内核版本：' + self.kernel_line())
        for kind in KINDS:
            print(self.status_line(kind))
        if not menu:
            print(paint('CYAN', BAR))
            return
        print('')
        print(paint('BLUE', '=== 协议 ==='))
        print(paint('GREEN', '1.') + ' 安装协议')
        print(paint('GREEN', '2.') + ' 管理协议（查看 / 修改 / 启停 / 卸载）')
        print('')
        print(paint('BLUE', '=== 内核 ==='))
        print(paint('GREEN', '3.') + ' 更新内核')
        print(paint('GREEN', '0.') + ' 退出脚本')
        print(paint('CYAN', BAR), flush=True)


def check(binary, data, root, directory, source_tls=False, modern=False):
    temporary_data = copy.deepcopy(data)

    def rebase(value):
        if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value) or '..' in Path(value).parts:
            reject()
        path = root / value.lstrip('/')
        if not path.resolve().is_relative_to(root):
            reject()
        return str(path)

    def fields(block, keys):
        if not isinstance(block, dict):
            return  # let kat check reject invalid advanced block types
        for key in keys:
            if block.get(key):
                block[key] = rebase(block[key])

    tls = temporary_data['inbounds'][0].get('tls')
    if tls:
        pairs = ([tls] if tls.get('cert') or tls.get('key') else []) + tls.get('certificates', [])
        for pair in pairs:
            if not source_tls:
                fields(pair, ('cert', 'key'))
            if not modern:
                certificate(Path(pair['cert']), Path(pair['key']))
            # The kernel validates modern file-following/multi-cert/ACME TLS.
            # Keep private-key permissions and staging containment constraints.
            key = Path(pair['key']).resolve()
            if key.stat().st_mode & 0o077 or key.parent.stat().st_mode & 0o077:
                reject()
        acme = tls.get('acme')
        if isinstance(acme, dict):
            fields(acme, ('storage', 'webroot', 'directory_ca'))
            fields(acme.get('dns'), ('api_token_file',))
    for outbound in temporary_data.get('outbounds', []):
        if isinstance(outbound, dict):
            fields(outbound.get('tls'), ('ca',))
    for source in [*temporary_data.get('rule_sets', []), *temporary_data.get('providers', []),
                   *[temporary_data[k] for k in ('geoip', 'geosite', 'asn') if k in temporary_data]]:
        fields(source, ('path',))
    for block, keys in (('log', ('file',)), ('stats', ('file',)), ('api', ('socket',))):
        fields(temporary_data.get(block), keys)
    # The stored data is never changed. check does not bind listeners, fetch
    # subscriptions or issue certificates; discard potentially private errors.
    with tempfile.NamedTemporaryFile(mode='w', prefix='.kat-check-', dir=directory, encoding='utf-8') as f:
        f.write(json.dumps(temporary_data, ensure_ascii=False, indent=2) + '\n')
        f.flush()
        result = subprocess.run([binary, 'check', f.name], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=15, cwd=root)
    if result.returncode:
        reject()


# ---------------------------------------------------------------- node output
# Surge: comma-separated "key=value"; a value containing anything beyond these
# characters is double-quoted with \" and \\ escapes (Surge profile "Quoted
# Values"). Generated credentials never need quoting.
SURGE_PLAIN = re.compile(r'[A-Za-z0-9+/=._-]+')
SURGE_POSITIONAL = re.compile(r'[A-Za-z0-9._-]+')


def surge_quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def display(kind, host, value):
    """Node information. Colours wrap whole values/lines only: without ANSI the
    text is exactly the plain output (snapshot-tested)."""
    text(host)
    address = '[' + host + ']' if ':' in host and not host.startswith('[') else host
    p, password = value['port'], value['password']
    rule = paint('CYAN', '------------------------------------------')

    def field(label, data):
        print(label + ': ' + paint('GREEN', data))

    def line(label, data):
        print(label + ':\n' + paint('GREEN', data))

    def mihomo(entry):
        line('Mihomo', '  - ' + json.dumps(entry, ensure_ascii=False, separators=(',', ':')))
    print(rule)
    print('Kat ' + kind + ' 当前配置')
    field('地址', host)
    field('端口', str(p))
    if kind == 'socks5':
        field('用户名', value['username'])
    field('密码', password)
    if kind in CERT_DIR and value.get('tls_manual'):
        warn('该TLS配置需自行按配置设置客户端；不生成 Surge/Mihomo/URI，不能据配置确认 ACME 已签发或推定验证策略')
        print(rule, flush=True)
        return
    if kind == 'ss':
        method = value['method']
        auth = method + ':' + quote(password, safe='') if method.startswith('2022-') else base64.urlsafe_b64encode((method + ':' + password).encode()).decode().rstrip('=')
        surge = password if SURGE_PLAIN.fullmatch(password) else surge_quote(password)
        field('加密', method)
        line('Surge', 'VPS = ss, ' + address + ', ' + str(p) + ', encrypt-method=' + method + ', password=' + surge + ', udp-relay=true')
        mihomo({'name': 'VPS', 'type': 'ss', 'server': host, 'port': p, 'cipher': method, 'password': password, 'udp': True})
        line('URI', 'ss://' + auth + '@' + address + ':' + str(p) + '#VPS')
    elif kind == 'anytls':
        line('Surge', 'VPS = anytls, ' + address + ', ' + str(p) + ', password=' + json.dumps(password, ensure_ascii=False) + ', skip-cert-verify=true, udp-relay=true')
        # "udp":true is required: without it mihomo treats the node as TCP-only
        # and sends UDP direct from the client (the AnyTLS-Manager line lacked it).
        mihomo({'name': 'VPS', 'server': host, 'port': p, 'password': password, 'skip-cert-verify': True, 'type': 'anytls', 'udp': True})
        # RFC 3986 userinfo: '/' must be percent-encoded too (an unencoded '/'
        # ends the authority and breaks standard URI parsers).
        line('URI', 'anytls://' + quote(password, safe='') + '@' + address + ':' + str(p) + '?security=tls&type=tcp&allowInsecure=1&insecure=1#VPS')
    elif kind == 'trojan':
        supplied = value.get('policy') == 'supplied'
        sni = value.get('sni')
        print('证书: ' + ('自备证书，客户端校验证书，SNI ' + sni if supplied else '自签证书，客户端需跳过证书校验'))
        line('Surge', 'VPS = trojan, ' + address + ', ' + str(p) + ', password=' + surge_quote(password) +
             (', sni=' + sni if supplied else ', skip-cert-verify=true') + ', udp-relay=true')
        entry = {'name': 'VPS', 'type': 'trojan', 'server': host, 'port': p, 'password': password}
        entry.update({'sni': sni} if supplied else {'skip-cert-verify': True})
        entry['udp'] = True
        mihomo(entry)
        query = 'security=tls&type=tcp&' + ('sni=' + quote(sni, safe='') if supplied else 'allowInsecure=1&insecure=1')
        line('URI', 'trojan://' + quote(password, safe='') + '@' + address + ':' + str(p) + '?' + query + '#VPS')
    else:
        username = value['username']
        print(paint('YELLOW', SOCKS5_WARNING))
        if SURGE_POSITIONAL.fullmatch(username) and SURGE_POSITIONAL.fullmatch(password):
            creds = ', ' + username + ', ' + password
        else:
            creds = ', username=' + surge_quote(username) + ', password=' + surge_quote(password)
        line('Surge', 'VPS = socks5, ' + address + ', ' + str(p) + creds + ', udp-relay=true')
        mihomo({'name': 'VPS', 'type': 'socks5', 'server': host, 'port': p, 'username': username, 'password': password, 'udp': True})
        line('URI', 'socks5://' + quote(username, safe='') + ':' + quote(password, safe='') + '@' + address + ':' + str(p) + '#VPS')
    print(rule, flush=True)


# ------------------------------------------------------------- interactive
class Menu:
    """Home page in the SS-Rust-Manager style. Every prompt reads /dev/tty
    (stdin may be the piped script); every action ends with 按回车继续..."""

    def __init__(self, base):
        self.base = base

    def args(self, action, kind, **values):
        a = argparse.Namespace(**vars(self.base))
        a.action, a.kind = action, kind
        for key, value in values.items():
            setattr(a, key, value)
        return a

    def manager(self, action='status', kind=None):
        return Manager(self.args(action, kind))

    def execute(self, action, kind=None, **values):
        manager = Manager(self.args(action, kind, **values))
        try:
            manager.run()
            return True
        except Fail as e:
            err(str(e))
        except SystemExit as e:
            return not e.code
        except (ValueError, KeyError, TypeError, OSError, RuntimeError, subprocess.SubprocessError):
            err(ERROR)
        return False

    @staticmethod
    def pause():
        return ask('按回车继续...') is not None

    @staticmethod
    def heading(title):
        print(paint('CYAN', BAR))
        print(paint('BLUE', '=== ' + title + ' ==='))

    @staticmethod
    def item(number, label):
        print(paint('GREEN', str(number) + '.') + ' ' + label)

    def pick(self, title):
        """Protocol chooser; returns a kind, or None for 返回 / invalid."""
        clear_screen()
        self.heading(title)
        status = self.manager()
        for index, kind in enumerate(KINDS, 1):
            self.item(index, status.status_line(kind))
        self.item(0, '返回')
        print(paint('CYAN', BAR), flush=True)
        answer = ask('请选择协议 [0-' + str(len(KINDS)) + ']: ')
        if answer and answer.isascii() and answer.isdigit() and 1 <= int(answer) <= len(KINDS):
            return KINDS[int(answer) - 1]
        return None

    def port(self, question):
        while True:
            answer = ask(question)
            if not answer:
                return None
            if answer.isascii() and answer.isdigit() and 1 <= int(answer) <= 65535:
                return int(answer)
            err('端口应为 1-65535')

    def install(self):
        kind = self.pick('安装协议')
        if not kind:
            return None
        values = {}
        if kind == 'socks5':
            warn(SOCKS5_WARNING[2:])
        values['port'] = self.port('端口（回车随机 10000-65535）: ')
        if kind == 'ss':
            methods = list(METHODS)
            for index, method in enumerate(methods, 1):
                self.item(index, method + ('（默认）' if method == DEFAULT_METHOD else ''))
            answer = ask('加密方式（回车默认 ' + DEFAULT_METHOD + '）: ')
            values['method'] = methods[int(answer) - 1] if answer and answer.isdigit() and 1 <= int(answer) <= len(methods) else DEFAULT_METHOD
        if kind == 'socks5':
            values['username'] = ask('用户名（回车随机）: ') or None
        values['credential'] = ask(('密钥' if kind == 'ss' and values['method'].startswith('2022-') else '密码') + '（回车随机生成）: ') or None
        if kind == 'trojan':
            cert = ask('自备证书路径（回车使用自签证书）: ')
            if cert:
                values['cert'] = Path(cert)
                values['key'] = Path(ask('私钥路径: ') or '/nonexistent')
                values['sni'] = ask('客户端 SNI 域名（回车取证书中的域名）: ') or None
        return self.execute('install', kind, **values)

    def modify(self, kind):
        values = {}
        values['port'] = self.port('新端口（回车不变）: ')
        if kind == 'socks5':
            values['username'] = ask('新用户名（回车不变）: ') or None
        answer = ask('新' + ('密钥' if kind == 'ss' else '密码') + '（回车不变，输入 r 随机生成）: ')
        if answer in ('r', 'R'):
            method = None
            if kind == 'ss':
                item = self.manager('view', kind).load(kind)
                method = item['current']['method'] if item else DEFAULT_METHOD
            values['credential'] = random_credential(kind, method)
        elif answer:
            values['credential'] = answer
        if not any(values.values()):
            info('未做修改')
            return True
        return self.execute('modify', kind, **values)

    def manage(self):
        kind = self.pick('管理协议')
        if not kind:
            return True
        state, detail = self.manager().probe(kind)
        if state == '未安装':
            err('Kat ' + LABEL[kind] + ' 未安装；请在“安装协议”中安装')
            return self.pause()
        if state == '已存在（非本脚本安装）':
            err('Kat ' + LABEL[kind] + ' 已存在（非本脚本安装）：' + detail + '；本脚本不管理它')
            return self.pause()
        actions = [('查看配置', 'view'), ('修改配置', 'modify'), ('启动', 'start'), ('停止', 'stop'), ('重启', 'restart'),
                   ('查看状态', 'status'), ('卸载', 'uninstall'), ('查看日志', 'logs')]
        while True:
            clear_screen()
            self.heading('管理 ' + LABEL[kind])
            print(self.manager().status_line(kind))
            print('')
            for index, (label, _) in enumerate(actions, 1):
                self.item(index, label)
            self.item(0, '返回')
            print(paint('CYAN', BAR), flush=True)
            choice = ask('请输入选项 [0-' + str(len(actions)) + ']: ')
            if choice is None:
                return False
            if choice == '0':
                return True
            if not (choice.isascii() and choice.isdigit() and 1 <= int(choice) <= len(actions)):
                err('无效选项')
            else:
                action = actions[int(choice) - 1][1]
                if action == 'modify':
                    self.modify(kind)
                elif action == 'logs':
                    answer = ask('日志：回车最近100行，f实时跟随，0取消: ')
                    if answer == '' or answer in ('f', 'F'):
                        self.execute('logs', kind, follow=bool(answer))
                    else:
                        info('已取消')
                elif action == 'uninstall':
                    if (ask('确认卸载 Kat ' + LABEL[kind] + '（停止并禁用 kat-' + kind + '.service）？[y/N]: ') or '').lower() in ('y', 'yes'):
                        self.execute('uninstall', kind)
                        return self.pause()
                    info('已取消')
                else:
                    self.execute(action, kind)
            if not self.pause():
                return False

    def loop(self):
        if not have_tty():
            self.manager().overview()
            err('未检测到交互终端（/dev/tty）；非交互使用请带参数，见 bash kat.sh help')
            return 1
        while True:
            clear_screen()
            self.manager().overview(menu=True)
            choice = ask('请输入选项 [0-3]: ')
            if choice is None or choice == '0':
                return 0
            if choice == '1':
                if self.install() is None:
                    continue
            elif choice == '2':
                if not self.manage():
                    return 0
                continue
            elif choice == '3':
                version = ask('目标版本（回车 latest）: ')
                self.execute('update', None, version=version or None)
            else:
                err('无效选项')
            print('')
            if not self.pause():
                return 0


# ------------------------------------------------------------------- CLI
def port_number(value):
    if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= 65535:
        raise argparse.ArgumentTypeError('端口应为 1-65535')
    return int(value)


def log_lines(value):
    if not value.isascii() or not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError('--lines 应为正整数')
    return int(value)


def parser():
    p = argparse.ArgumentParser(prog='bash kat.sh', add_help=False, usage='bash kat.sh [动作] [协议] [参数]（bash kat.sh help）')
    p.add_argument('words', nargs='*')
    p.add_argument('-h', '--help', action='store_true')
    p.add_argument('--version')
    p.add_argument('--binary', type=Path)
    p.add_argument('--sha256')
    p.add_argument('--listen', dest='address')
    p.add_argument('--port', type=port_number)
    p.add_argument('--method')
    p.add_argument('--credential-file', type=Path)
    p.add_argument('--username')
    p.add_argument('--cert', type=Path)
    p.add_argument('--key', type=Path)
    p.add_argument('--sni')
    p.add_argument('--tls-policy', choices=('legacy-insecure',))
    p.add_argument('--ack-certificate-change', action='store_true')
    p.add_argument('--host')
    p.add_argument('--purge', action='store_true')
    p.add_argument('--lines', type=log_lines)
    p.add_argument('--follow', action='store_true')
    p.add_argument('--root', type=Path, default=Path('/'))
    p.add_argument('--offline', action='store_true')
    return p


def arguments(argv):
    a = parser().parse_args(argv)
    a.credential = None
    words = [w.lower() for w in a.words]
    if a.help or words[:1] in (['help'], ['-h']):
        a.action, a.kind = 'help', None
        return a
    if not words:
        a.action, a.kind = 'menu', None
        return a
    if len(words) == 2 and words[0] in ALIASES and words[1] in PROTOCOL_ACTIONS:
        words.reverse()                     # "kat.sh ss install" == "kat.sh install ss"
    action = words[0]
    kind = ALIASES.get(words[1]) if len(words) > 1 else None
    if len(words) > 2 or (len(words) > 1 and kind is None):
        fail('无法识别的参数：' + ' '.join(a.words) + '（协议为 ss / anytls / trojan / socks5，见 bash kat.sh help）')
    if action in ('update', 'menu') and kind:
        fail(action + ' 作用于共享内核和所有 Kat 服务，不带协议')
    if action in PROTOCOL_ACTIONS and action != 'status' and not kind:
        fail(action + ' 需要指定协议：ss / anytls / trojan / socks5')
    if action not in PROTOCOL_ACTIONS and action not in GLOBAL_ACTIONS:
        fail('未知动作：' + action + '（见 bash kat.sh help）')
    if action != 'logs' and (a.lines is not None or a.follow):
        fail('--lines/--follow 仅用于 logs')
    a.action, a.kind = action, kind
    return a


def main(argv):
    a = arguments(argv)
    if a.action == 'help':
        print(USAGE)
        return 0
    if a.action == 'menu':
        if os.geteuid() != 0:
            fail('请用 root 运行')
        Manager(a)                          # validates --root/--offline
        return Menu(a).loop()
    return Manager(a).run() or 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except Fail as e:
        err(str(e))
        sys.exit(1)
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, RecursionError, subprocess.SubprocessError):
        err(ERROR)
        sys.exit(1)

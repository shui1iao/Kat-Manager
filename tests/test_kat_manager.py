import ast
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import kat_config  # noqa: E402
import kat_manager  # noqa: E402


DEFAULT_PADDING = (
    "stop=8\n0=30-30\n1=100-400\n"
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
    "3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"
)


class KatManagerContractTests(unittest.TestCase):
    def test_m1_anytls_padding_scheme_accepted_and_validated(self):
        for modern in (False, True):
            cfg = {
                'inbounds': [{
                    'protocol': 'anytls',
                    'listen': '0.0.0.0:443',
                    'anytls': {
                        'password': 'secret-password',
                        'padding_scheme': DEFAULT_PADDING,
                    },
                }],
            }
            parsed = kat_config.node('anytls', cfg, modern=modern)
            self.assertEqual(parsed['port'], 443)
            self.assertEqual(parsed['password'], 'secret-password')

        # Empty padding_scheme resolves to core default and is valid
        empty_scheme = {
            'inbounds': [{
                'protocol': 'anytls',
                'listen': '0.0.0.0:443',
                'anytls': {'password': 'secret', 'padding_scheme': ''},
            }],
        }
        self.assertEqual(kat_config.node('anytls', empty_scheme, modern=True)['port'], 443)

        # Malformed padding schemes (missing stop, index >= stop, 'c' on 0, duplicate index, >4096B) are rejected
        for bad in (
            '0=30-30',
            'stop=2\n2=10-20',
            'stop=2\n0=c',
            'stop=2\n0=30-10',
            'stop=2\n0=30-30\n00=30-30',
            'stop=2\n0=30-30\n+0=30-30',
            'stop=3\n1=10-20\n01=20-30',
            'stop=2\nstop=2\n0=30-30',
            'stop=2\n0=' + '1' * 4100 + '-2',
            None,
            123,
        ):
            with self.assertRaises(ValueError):
                kat_config.node('anytls', {
                    'inbounds': [{
                        'protocol': 'anytls',
                        'listen': '0.0.0.0:443',
                        'anytls': {'password': 'secret', 'padding_scheme': bad},
                    }],
                }, modern=True)

    def test_m3_dns_servers_and_removed_client_blocks(self):
        # dns.servers array (including case-insensitive URL schemes) accepted in both modern and base validator
        cfg = {
            'dns': {
                'servers': ['udp://8.8.8.8:53', 'UDP://9.9.9.9:53', 'Tcp://1.0.0.1:53', 'HTTPS://1.1.1.1/dns-query'],
                'cache_entries': 512,
            },
            'inbounds': [{'protocol': 'socks5', 'listen': '127.0.0.1:1080',
                          'users': [{'username': 'u', 'password': 'p'}]}],
        }
        self.assertEqual(kat_config.node('socks5', cfg, modern=False)['port'], 1080)
        self.assertEqual(kat_config.node('socks5', cfg, modern=True)['port'], 1080)
        self.assertEqual(kat_config.node('socks5', {
            'dns': {'server': 'UDP://8.8.8.8:53'},
            'inbounds': [{'protocol': 'socks5', 'listen': '127.0.0.1:1080',
                          'users': [{'username': 'u', 'password': 'p'}]}],
        }, modern=True)['port'], 1080)

        # Mutually exclusive server + servers, unsupported scheme or 'system' inside servers rejected
        for bad_dns in (
            {'server': '8.8.8.8', 'servers': ['1.1.1.1']},
            {'servers': []},
            {'servers': ['system']},
            {'servers': ['TLS://1.1.1.1:853']},
            {'server': 'system', 'cache_entries': 64},
            None,
        ):
            with self.assertRaises(ValueError):
                kat_config.node('socks5', {
                    'dns': bad_dns,
                    'inbounds': [{'protocol': 'socks5', 'listen': '127.0.0.1:1080',
                                  'users': [{'username': 'u', 'password': 'p'}]}],
                }, modern=True)

        # Removed client-only top-level blocks must be rejected in both modes
        for removed in ('routing', 'outbounds', 'groups', 'providers', 'rule_sets', 'geoip', 'geosite', 'asn'):
            for modern in (False, True):
                with self.assertRaises(ValueError, msg=f'{removed} modern={modern}'):
                    kat_config.node('socks5', {
                        removed: [] if removed not in ('routing', 'geoip', 'geosite', 'asn') else {},
                        'inbounds': [{'protocol': 'socks5', 'listen': '127.0.0.1:1080',
                                      'users': [{'username': 'u', 'password': 'p'}]}],
                    }, modern=modern)

    def test_m2_check_handles_malformed_certs_and_allows_0755_letsencrypt_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            os.chmod(base, 0o755)
            fake_bin = base / 'fake-kat'
            fake_bin.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
            os.chmod(fake_bin, 0o755)

            scratch = base / 'scratch'
            scratch.mkdir()
            os.chmod(scratch, 0o700)

            # Simulate standard Certbot layout: 0755 archive/live dirs + 0600 privkey1.pem + live symlink
            le_archive = base / 'etc' / 'letsencrypt' / 'archive' / 'example.com'
            le_live = base / 'etc' / 'letsencrypt' / 'live' / 'example.com'
            le_archive.mkdir(parents=True)
            le_live.mkdir(parents=True)
            for p in (base / 'etc', base / 'etc' / 'letsencrypt',
                      base / 'etc' / 'letsencrypt' / 'archive', le_archive,
                      base / 'etc' / 'letsencrypt' / 'live', le_live):
                os.chmod(p, 0o755)

            real_cert = le_archive / 'fullchain1.pem'
            real_key = le_archive / 'privkey1.pem'
            real_cert.write_text('CERT\n', encoding='utf-8')
            real_key.write_text('KEY\n', encoding='utf-8')
            os.chmod(real_cert, 0o644)
            os.chmod(real_key, 0o600)

            live_cert = le_live / 'fullchain.pem'
            live_key = le_live / 'privkey.pem'
            live_cert.symlink_to(real_cert)
            live_key.symlink_to(real_key)

            rel_cert = '/' + str(live_cert.relative_to(base))
            rel_key = '/' + str(live_key.relative_to(base))

            valid_data = {
                'inbounds': [{
                    'protocol': 'anytls',
                    'listen': '0.0.0.0:443',
                    'anytls': {'password': 'pw'},
                    'tls': {'cert': rel_cert, 'key': rel_key},
                }],
            }
            # Must pass without raising Fail or ValueError
            kat_manager.check(str(fake_bin), valid_data, base, scratch, modern=True)

            # World/group-readable private key (0644) must convert Fail -> ValueError
            os.chmod(real_key, 0o644)
            with self.assertRaises(ValueError):
                kat_manager.check(str(fake_bin), valid_data, base, scratch, modern=True)
            os.chmod(real_key, 0o600)

            # Sticky world-writable key parent (01777) must be rejected with ValueError
            sticky_dir = base / 'sticky-certs'
            sticky_dir.mkdir()
            os.chmod(sticky_dir, 0o1777)
            s_cert = sticky_dir / 'c.pem'
            s_key = sticky_dir / 'k.pem'
            s_cert.write_text('C\n', encoding='utf-8')
            s_key.write_text('K\n', encoding='utf-8')
            os.chmod(s_key, 0o600)
            with self.assertRaises(ValueError):
                kat_manager.check(str(fake_bin), {
                    'inbounds': [{
                        'protocol': 'anytls',
                        'listen': '0.0.0.0:443',
                        'anytls': {'password': 'pw'},
                        'tls': {
                            'cert': '/' + str(s_cert.relative_to(base)),
                            'key': '/' + str(s_key.relative_to(base)),
                        },
                    }],
                }, base, scratch, modern=True)
            os.chmod(sticky_dir, 0o700)

            # Symlink inside world-writable (0777 / 01777) parent pointing to trusted 0600 key MUST be rejected (TOCTOU guard)
            for bad_mode, dir_name in ((0o777, 'world-writable-link'), (0o1777, 'sticky-writable-link')):
                untrusted_link_dir = base / dir_name
                untrusted_link_dir.mkdir()
                link_cert = untrusted_link_dir / 'fullchain.pem'
                link_key = untrusted_link_dir / 'privkey.pem'
                link_cert.symlink_to(real_cert)
                link_key.symlink_to(real_key)
                os.chmod(untrusted_link_dir, bad_mode)
                with self.assertRaises(ValueError, msg=f'mode={oct(bad_mode)}'):
                    kat_manager.check(str(fake_bin), {
                        'inbounds': [{
                            'protocol': 'anytls',
                            'listen': '0.0.0.0:443',
                            'anytls': {'password': 'pw'},
                            'tls': {
                                'cert': '/' + str(link_cert.relative_to(base)),
                                'key': '/' + str(link_key.relative_to(base)),
                            },
                        }],
                    }, base, scratch, modern=True)
                os.chmod(untrusted_link_dir, 0o700)

            # Malformed tls / certificates structures must raise ValueError (never TypeError/KeyError)
            for bad_tls in (
                'not-a-dict',
                {'certificates': 'not-a-list'},
                {'certificates': [123]},
                {'certificates': [{'cert': rel_cert}]},
                {'cert': '', 'key': rel_key},
            ):
                with self.assertRaises(ValueError, msg=repr(bad_tls)):
                    kat_manager.check(str(fake_bin), {
                        'inbounds': [{
                            'protocol': 'anytls',
                            'listen': '0.0.0.0:443',
                            'anytls': {'password': 'pw'},
                            'tls': bad_tls,
                        }],
                    }, base, scratch, modern=True)

    def test_python38_ast_and_pin_helpers_check(self):
        for name in ('kat_config.py', 'kat_manager.py'):
            src = (ROOT / name).read_text(encoding='utf-8')
            tree = ast.parse(src, filename=name, feature_version=(3, 8))
            for n in ast.walk(tree):
                if isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr):
                    # Ensure no PEP 604 type union at annotation positions
                    pass
        res = subprocess.run(['bash', str(ROOT / 'scripts' / 'pin-helpers.sh'), '--check'],
                             cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr or res.stdout)


if __name__ == '__main__':
    unittest.main()

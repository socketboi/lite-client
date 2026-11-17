"""Exercise the real CLI and service startup with network/procd/sysctl effects stubbed."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.hy=Path(os.environ['LC_TUNNEL_HY1']).resolve()
        self.reality=Path(os.environ['LC_TUNNEL_HY0']).resolve()
        self.assertIn('hysteria',subprocess.check_output([self.hy,'--planes'],text=True))
        self.assertNotIn('hysteria',subprocess.check_output([self.reality,'--planes'],text=True))
        directory=tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.root=Path(directory.name)
        shutil.copyfile('package/files/fingerprint.fpt',self.root/'fingerprint.fpt')
        (self.root/'uuid').write_text('00000000-0000-4000-8000-000000000001\n')
        (self.root/'auth').write_text('fixture-auth\n')
        for name in ('uuid','auth'): (self.root/name).chmod(0o600)
        self.port=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
        self.port.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
        self.port.bind(('::',0)); self.port.listen()
        self.addCleanup(self.port.close)

    def args(self,hy=False):
        if hy:
            return ['-H','offline.invalid','443','config.test','@'+str(self.root/'auth'),'-',
                    str(self.port.getsockname()[1]),'-p','-','--check-config']
        return [str(self.root/'fingerprint.fpt'),'offline.invalid','443','config.test','00'*32,
                '0123abcd','@'+str(self.root/'uuid'),str(self.port.getsockname()[1]),'-w','4','--check-config']

    def cli(self,args,code=0,binary=None,env=None):
        value=subprocess.run([binary or self.hy,*args],capture_output=True,text=True,timeout=5,env=env)
        self.assertEqual(value.returncode,code,value.stdout+value.stderr)
        return value

    def test_reality_check_needs_no_listener_privilege_or_node(self):
        self.cli(self.args(),binary=self.reality)

    def test_hysteria_check_needs_no_listener_or_node(self):
        self.cli(self.args(hy=True))

    def test_missing_plane_is_refused(self):
        self.cli(self.args(hy=True),2,self.reality)

    def test_invalid_udp_target_is_refused_without_forking(self):
        self.cli(self.args()+['-u','19600@invalid:'],2)

    def test_invalid_fixed_target_is_refused(self):
        self.cli(self.args()+['-t','[::1]:bad'],2)

    def test_broken_fingerprint_is_refused(self):
        (self.root/'fingerprint.fpt').write_bytes(b'broken')
        self.cli(self.args(),2)

    def test_special_fingerprint_files_are_refused_without_blocking(self):
        table=self.root/'fingerprint.fpt'
        table.unlink()
        os.mkfifo(table,0o600)
        self.cli(self.args(),2)
        writer=os.open(table,os.O_RDWR|os.O_NONBLOCK)
        try:
            self.cli(self.args(),2)
        finally:
            os.close(writer)
        table.rename(self.root/'fifo')
        table.symlink_to(self.root/'fifo')
        self.cli(self.args(),2)
        table.unlink(); table.symlink_to('/dev/zero')
        self.cli(self.args(),2)
        table.unlink(); table.mkdir()
        self.cli(self.args(),2)

    def test_service_fingerprint_fifo_is_refused_before_effects(self):
        (self.root/'fingerprint.fpt').unlink()
        os.mkfifo(self.root/'fingerprint.fpt',0o600)
        self.service(1)

    def test_public_fingerprint_regular_symlink_remains_supported(self):
        table=self.root/'fingerprint.fpt'
        table.rename(self.root/'regular.fpt')
        table.symlink_to(self.root/'regular.fpt')
        self.cli(self.args(),binary=self.reality)

    def test_read_error_after_valid_fingerprint_prefix_is_refused(self):
        # The read returns the complete valid table, then EIO instead of EOF.
        # A parser alone cannot distinguish this failure from successful input.
        source=self.root/'io-error.c'
        source.write_text('''#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct input { int fd; };
static ssize_t broken_read(void *arg, char *buf, size_t len) {
    struct input *c=arg;
    ssize_t n=read(c->fd,buf,len);
    if (n==0) { errno=EIO; return -1; }
    return n;
}
static int end_read(void *arg) {
    struct input *c=arg; int result=close(c->fd); free(c); return result;
}
FILE *fdopen(int fd, const char *mode) {
    struct input *c=malloc(sizeof *c);
    if (!c) return NULL;
    c->fd=fd;
    cookie_io_functions_t ops={ .read=broken_read, .close=end_read };
    FILE *f=fopencookie(c,mode,ops);
    if (!f) free(c);
    return f;
}
''')
        library=self.root/'io-error.so'
        subprocess.run(['cc','-shared','-fPIC',str(source),'-o',str(library)],check=True,capture_output=True)
        self.cli(self.args(),2,binary=self.reality,env=dict(os.environ,LD_PRELOAD=str(library)))

    def test_uuid_fifo_does_not_block_validation(self):
        (self.root/'uuid').unlink()
        os.mkfifo(self.root/'uuid',0o600)
        self.cli(self.args(),2)

    def test_auth_fifo_does_not_block_validation(self):
        (self.root/'auth').unlink()
        os.mkfifo(self.root/'auth',0o600)
        self.cli(self.args(hy=True),2)

    def service(self,expected,plane='reality',binary=None,clients='',enabled='1',active=True):
        script='''
. ./package/files/lite-client.init
PROG=$TEST_BINARY
STATE=$TEST_ROOT
EVENTS=$TEST_ROOT/native-events
CONF=$TEST_ROOT/config
PRESERVED="$STATE/uuid $STATE/auth $STATE/obfs"
config_load() { :; }
config_get_bool() { case "$TEST_ENABLED" in 1|yes|true|on) eval "$1=1";; *) eval "$1=0";; esac; }
config_get() {
    local value
    case "$3" in
    enabled) value=$TEST_ENABLED;; plane) value=$TEST_PLANE;; node) value=offline.invalid;;
    sni) value=config.test;; public_key) value=$(printf '%064d' 0);;
    short_id) value=0123abcd;; workers) value=1;; pin) value=-;;
    clients) value=$TEST_CLIENTS;;
    *) value=${4-};;
    esac
    eval "$1=\\$value"
}
logger() { printf '%s\\n' "$*" >> "$TEST_ROOT/log"; }
lc_rules_down() { echo cleanup >> "$TEST_ROOT/effects"; }
lc_tune_tcp() { echo tune >> "$TEST_ROOT/effects"; }
procd_open_instance() { echo open >> "$TEST_ROOT/effects"; }
procd_set_param() {
    if [ "$1" = command ]; then shift; printf '%s\\n' "$@" > "$TEST_ROOT/command"; fi
    if [ "$1" = file ]; then shift; printf '%s\\n' "$@" > "$TEST_ROOT/watched"; fi
}
procd_close_instance() { echo close >> "$TEST_ROOT/effects"; }
lc_rules_up() { echo rules >> "$TEST_ROOT/effects"; }
start_service
'''
        script=script.replace('. ./package/files/lite-client.init', '. "$TEST_INIT"')
        env=dict(os.environ,TEST_BINARY=str(binary or self.hy),TEST_ROOT=str(self.root),TEST_PLANE=plane,
                 TEST_CLIENTS=clients,TEST_ENABLED=enabled,
                 TEST_INIT=str(Path(os.environ.get('LC_INIT','package/files/lite-client.init')).resolve()))
        value=subprocess.run(['sh','-c',script],env=env,capture_output=True,text=True,timeout=5)
        self.assertEqual(value.returncode,expected,value.stdout+value.stderr)
        effects=self.root/'effects'
        if expected or not active:
            self.assertEqual(effects.read_text().splitlines(),['cleanup'],
                             'invalid config must only clean previous interception')
        else:
            self.assertEqual(effects.read_text().splitlines(),['cleanup','tune','open','close','rules'])
            command=(self.root/'command').read_text().splitlines()
            self.assertEqual(command[0],str(binary or self.hy))
            self.assertNotIn('--check-config',command,'procd must run the tunnel, not its validator')
            self.assertIn('@'+str(self.root/('auth' if plane=='hysteria' else 'uuid')),command)
            self.assertEqual((self.root/'watched').read_text().splitlines(),
                             [str(self.root/'config'),str(binary or self.hy),str(self.root/'fingerprint.fpt')])
        log=(self.root/'log').read_text() if (self.root/'log').exists() else ''
        self.assertNotIn('fixture-auth',log,'credential contents must not reach syslog')

    def test_service_valid_reality(self):
        self.service(0)

    def test_service_valid_hysteria(self):
        self.service(0,'hysteria')

    def test_service_disabled(self):
        self.service(0,enabled='0',active=False)

    def test_service_invalid_enabled_value(self):
        self.service(1,enabled='typo',active=False)

    def test_service_valid_clients(self):
        self.service(0,clients='192.0.2.7 198.51.100.0/24')

    def test_service_ipv6_client_is_refused_before_effects(self):
        self.service(1,clients='2001:db8::7')

    def test_service_bad_client_prefix_is_refused_before_effects(self):
        self.service(1,clients='192.0.2.7 198.51.100.0/33')

    def test_service_bad_client_address_is_refused_before_effects(self):
        self.service(1,clients='192.0.2.999')

    def test_service_trailing_dot_client_is_refused_before_effects(self):
        self.service(1,clients='192.0.2.7.')

    def test_service_open_uuid_permissions(self):
        (self.root/'uuid').chmod(0o644)
        self.service(1)

    def test_service_bad_uuid_content(self):
        (self.root/'uuid').write_text('not-a-uuid\n')
        self.service(1)

    def test_service_uuid_symlink(self):
        (self.root/'uuid').rename(self.root/'real-uuid')
        (self.root/'uuid').symlink_to(self.root/'real-uuid')
        self.service(1)

    def test_service_open_auth_permissions(self):
        (self.root/'auth').chmod(0o644)
        self.service(1,'hysteria')

    def test_service_empty_auth(self):
        (self.root/'auth').write_text('\n')
        self.service(1,'hysteria')

    def test_service_broken_fingerprint(self):
        (self.root/'fingerprint.fpt').write_bytes(b'broken')
        self.service(1)

    def test_service_missing_plane(self):
        self.service(1,'hysteria',self.reality)


if __name__=='__main__': unittest.main()

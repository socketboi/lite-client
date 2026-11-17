"""Execute the SDK's real rc.common with UCI/procd/kernel commands simulated.

The service script and its validators/rule builder/teardown are real. This checks
shell lifecycle ordering, not a running procd daemon or kernel firewall behavior.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess


FUNCTIONS=r'''
list_contains() { eval "local values=\$$1"; case " $values " in *" $2 "*) return 0;; esac; return 1; }
config_load() { :; }
config_get_bool() { eval "$1=$TEST_ENABLED"; }
config_get() {
    local value
    case "$3" in
    enabled) value=$TEST_ENABLED;; clients) value=$TEST_CLIENTS;;
    node) value=203.0.113.7;; sni) value=config.test;;
    public_key) value=$(printf '%064d' 0);; short_id) value=0123abcd;; workers) value=1;;
    diagnostic_client_id) value=17;;
    *) value=${4-};;
    esac
    eval "$1=\$value"
}
'''

PROCD=r'''
procd_lock() { :; }
procd_open_service() { pending=0; echo open-service >> "$TEST_ROOT/events"; }
procd_open_instance() { pending=1; echo prepare-instance >> "$TEST_ROOT/events"; }
procd_set_param() { [ "$1" != env ] || printf '%s\n' "$*" >> "$TEST_ROOT/events"; }
procd_close_instance() { echo close-instance >> "$TEST_ROOT/events"; }
procd_close_service() { service_triggers; echo "$pending" > "$TEST_ROOT/registered"; echo publish-service >> "$TEST_ROOT/events"; }
procd_kill() { echo 0 > "$TEST_ROOT/registered"; echo kill-service >> "$TEST_ROOT/events"; }
procd_add_reload_trigger() { echo "reload-trigger $*" >> "$TEST_ROOT/events"; }
procd_add_interface_trigger() { echo "interface-trigger $*" >> "$TEST_ROOT/events"; }
'''

WRAPPER=r'''
. "$TEST_INIT"
PROG="$TEST_ROOT/client"
STATE="$TEST_ROOT/state"
EVENTS="$TEST_ROOT/native-events"
CONF="$TEST_ROOT/config"
logger() { printf '%s\n' "$*" >> "$TEST_ROOT/log"; }
lc_tune_tcp() { echo tune >> "$TEST_ROOT/events"; }
lc_wait_ready() { echo readiness >> "$TEST_ROOT/events"; return 0; }
ip() {
    printf 'ip %s\n' "$*" >> "$TEST_ROOT/events"
    case "$*" in
    'rule add '*) echo 1 > "$TEST_ROOT/rule";;
    '-4 rule del '*) [ -f "$TEST_ROOT/rule" ] || return 1; rm -f "$TEST_ROOT/rule";;
    '-6 rule del '*) return 1;;
    'route add '*) [ "$TEST_ROUTE_FAIL" = 0 ] || return 1; echo 1 > "$TEST_ROOT/route";;
    '-4 route flush '*) rm -f "$TEST_ROOT/route";;
    '-6 route flush '*) :;;
    *) return 2;;
    esac
}
nft() {
    printf 'nft %s\n' "$*" >> "$TEST_ROOT/events"
    case "$*" in
    'delete table inet lite_client') rm -f "$TEST_ROOT/nft";;
    '-f -') cat > "$TEST_ROOT/transaction"; [ "$TEST_NFT_FAIL" = 0 ] || return 1; echo 1 > "$TEST_ROOT/nft";;
    *) return 2;;
    esac
}
pgrep() { echo unexpected-pgrep >> "$TEST_ROOT/events"; return 0; }
'''


def main():
    if not __debug__: raise RuntimeError('qualification requires assertions enabled')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rc-common',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    rc=args.rc_common.resolve()
    if not rc.is_file(): raise FileNotFoundError(rc)
    output=args.output.resolve(); output.mkdir(parents=True,exist_ok=False)
    package_files=Path(__file__).resolve().parents[2]/'package/files'
    source=Path(os.environ.get('LC_INIT',str(package_files/'lite-client.init'))).resolve()
    receipts=[]

    def case(name):
        root=output/name
        (root/'lib/functions').mkdir(parents=True)
        (root/'lib/functions.sh').write_text(FUNCTIONS)
        (root/'lib/functions/service.sh').write_text('')
        (root/'lib/functions/procd.sh').write_text(PROCD)
        (root/'lite-client').write_text(WRAPPER)
        (root/'state').mkdir()
        (root/'state/uuid').write_text('00000000-0000-4000-8000-000000000001\n')
        (root/'state/fingerprint.fpt').write_bytes((package_files/'fingerprint.fpt').read_bytes())
        (root/'client').write_text('#!/bin/sh\n[ "$1" = --planes ] && { echo reality; exit 0; }\n[ "$1" != --version ] || echo fixture-version\nexit 0\n')
        (root/'client').chmod(0o755)
        (root/'unrelated').write_text('unrelated service fixture\n')
        return root

    def action(root,command,enabled='1',clients='192.0.2.7',nft='0',route='0',expected=0):
        env=dict(os.environ,IPKG_INSTROOT=str(root),TEST_ROOT=str(root),TEST_INIT=str(source),
                 TEST_ENABLED=enabled,TEST_CLIENTS=clients,TEST_NFT_FAIL=nft,TEST_ROUTE_FAIL=route)
        result=subprocess.run(['sh',str(rc),str(root/'lite-client'),command],env=env,
                              capture_output=True,text=True,timeout=10)
        (root/(command+'.output')).write_text(result.stdout+result.stderr)
        assert result.returncode==expected,(command,result.returncode,result.stderr)
        assert (root/'unrelated').read_text()=='unrelated service fixture\n'
        return (root/'events').read_text().splitlines()

    def clean(root):
        assert all(not (root/name).exists() for name in ('rule','route','nft'))

    root=case('start-stop')
    events=action(root,'start')
    assert f'env LC_EVENT_DIR={root}/native-events LC_SOURCE_VERSION=fixture-version LC_PLANE=reality LC_CLIENT_ID=17' in events
    assert events.index('prepare-instance')<events.index('nft -f -')<events.index('publish-service')
    assert events.index('publish-service')<events.index('readiness')
    assert 'reload-trigger lite-client' in events
    assert 'interface-trigger interface.*.up wan /etc/init.d/lite-client restart' in events
    assert (root/'registered').read_text().strip()=='1'
    assert all((root/name).exists() for name in ('rule','route','nft'))
    events=action(root,'stop'); clean(root)
    assert events.index('nft delete table inet lite_client',events.index('publish-service'))<events.index('kill-service')
    action(root,'stop'); clean(root)
    receipts.append('start/stop publication order and repeated stop')

    for command in ('start','reload','restart'):
        for label,enabled,clients in (('disabled','0','192.0.2.7'),('invalid','1','192.0.2.999')):
            root=case(command+'-'+label); action(root,'start')
            events=action(root,command,enabled,clients,expected=1 if label=='invalid' else 0); clean(root)
            assert (root/'registered').read_text().strip()=='0'
            assert events.count('prepare-instance')==1 and events.count('tune')==1
            if command!='start': assert events.index('kill-service')<len(events)-1
            receipts.append(command+' '+label+' removes old interception and instance')

    for failure in ('nft','route'):
        root=case(failure+'-failure')
        events=action(root,'start',nft='1' if failure=='nft' else '0',route='1' if failure=='route' else '0',expected=1)
        clean(root)
        # rc.common publishes prepared instances even when start_service returns nonzero.
        assert (root/'registered').read_text().strip()=='1'
        assert 'unexpected-pgrep' not in events
        assert 'the tunnel itself is running' not in (root/'log').read_text()
        action(root,'stop'); clean(root)
        receipts.append(failure+' failure rolls back rules without claiming process liveness')

    report=dict(validated=True,cases=receipts,scope=__doc__.strip())
    (output/'analysis.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__': main()

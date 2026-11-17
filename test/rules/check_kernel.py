"""Qualify routing/nft rollback in an explicitly isolated Docker network namespace.

The rollback gate does not qualify successful TPROXY installation. Use
--require-tproxy for that additional gate; unsupported kernels exit 77.
No packets are forwarded and no procd daemon is started.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--require-tproxy',action='store_true')
    args=parser.parse_args()
    if os.environ.get('LC_KERNEL_TEST_ISOLATED')!='1' or not Path('/.dockerenv').is_file():
        raise RuntimeError('requires explicit LC_KERNEL_TEST_ISOLATED=1 in Docker --network none')
    ip=shutil.which('ip'); nft=shutil.which('nft')
    if not ip or not nft: raise RuntimeError('requires iproute2 and nftables')
    links=json.loads(subprocess.check_output([ip,'-j','link','show'],text=True))
    if {link['ifname'] for link in links}!={'lo'}:
        raise RuntimeError('refusing a namespace containing interfaces other than lo')
    output=args.output.resolve(); output.mkdir(parents=True,exist_ok=False)
    source=Path(os.environ.get('LC_INIT',str(Path(__file__).resolve().parents[2]/'package/files/lite-client.init'))).resolve()

    def run(*command,check=True):
        result=subprocess.run([str(c) for c in command],capture_output=True,text=True,timeout=30)
        with (output/'commands.log').open('a') as log:
            log.write(' '.join(map(str,command))+'\n'+result.stdout+result.stderr+'\n')
        if check and result.returncode: raise RuntimeError(f'exit {result.returncode}: {command[:4]}; see commands.log')
        return result

    def query(*command): return json.loads(run(*command).stdout)

    def rules(family): return query(ip,*family,'-j','rule','show')

    def marked(rule,mark):
        value=rule.get('fwmark',0)
        return (int(value,0) if isinstance(value,str) else value)==mark

    def routes(family,table):
        return [r for r in query(ip,*family,'-j','route','show','table','all') if str(r.get('table'))==str(table)]

    def foreign():
        return dict(v4=[r for r in rules([]) if marked(r,0x50505)],
                    v6=[r for r in rules(['-6']) if marked(r,0x50505)],
                    routes4=routes([],105),routes6=routes(['-6'],105),
                    nft=query(nft,'-j','list','table','inet','lc_kernel_foreign'))

    run(ip,'link','set','lo','up')
    for family in ([],['-6']):
        run(ip,*family,'rule','add','priority','30001','fwmark','0x50505','lookup','105')
        run(ip,*family,'route','add','local','default','dev','lo','table','105')
    run(nft,'add','table','inet','lc_kernel_foreign')
    baseline=foreign()
    (output/'foreign-before.json').write_text(json.dumps(baseline,indent=2)+'\n')
    receipts=[]
    script=r'''
. "$TEST_INIT"
logger() { printf '%s\n' "$*" >&2; }
ip() {
    if [ "$TEST_FAULT" = route ] && [ "$*" = "route add local default dev lo table 104" ]; then
        "$TEST_IP" route add local default dev lc_missing table 104
    else
        "$TEST_IP" "$@"
    fi
}
nft() {
    printf 'NFT_CALL %s\n' "$*" >&2
    if [ "$TEST_FAULT" = nft ] && [ "$*" = "-f -" ]; then
        cat > "$TEST_TRANSACTION"
        printf '\nadd rule inet lite_client lc_missing_chain counter\n' >> "$TEST_TRANSACTION"
        "$TEST_NFT" -f "$TEST_TRANSACTION"
    else
        "$TEST_NFT" "$@"
    fi
}
"$@"
'''

    def service(label,action,*values,fault='none'):
        env=dict(os.environ,TEST_INIT=str(source),TEST_IP=ip,TEST_NFT=nft,
                 TEST_FAULT=fault,TEST_TRANSACTION=str(output/(label+'.nft')))
        result=subprocess.run(['sh','-c',script,'kernel-test',action,*values],env=env,
                              capture_output=True,text=True,timeout=30)
        (output/(label+'.log')).write_text(result.stdout+result.stderr)
        return result

    def clean():
        assert not any(marked(r,0x1000000) for family in ([],['-6']) for r in rules(family))
        assert not routes([],104) and not routes(['-6'],104)
        assert not any(item.get('table',{}).get('name')=='lite_client'
                       for item in query(nft,'-j','list','tables')['nftables'])
        assert foreign()==baseline,'unrelated rules/routes/table changed'

    def down(label):
        result=service(label,'lc_rules_down')
        assert result.returncode==0,result.stderr
        clean()

    down('empty-stop'); down('repeated-empty-stop')
    receipts.append('empty and repeated teardown preserve unrelated kernel state')
    for family in ([],['-6']):
        for table in (101,104):
            run(ip,*family,'rule','add','fwmark','0x40404','lookup',str(table))
        run(ip,*family,'route','add','local','default','dev','lo','table','104')
    run(nft,'add','table','inet','lite_client')
    down('legacy-stop')
    receipts.append('multiple IPv4/IPv6 rules including legacy table numbers are removed')

    for label,clients,fault in (
        ('invalid-prefix','192.0.2.7 198.51.100.0/33','none'),
        ('ipv6-client','2001:db8::7','none'),
        ('trailing-dot','192.0.2.7.','none'),
        ('route-failure','192.0.2.7','route'),
        ('nft-failure','192.0.2.7','nft'),
        ('external-marking-nft-failure','','nft'),
        ('repeated-nft-failure','192.0.2.7','nft')
    ):
        result=service(label,'lc_rules_up','19099',clients,'203.0.113.7','19098',fault=fault)
        assert result.returncode!=0,label
        if fault=='route':
            assert 'lc_missing' in result.stderr and 'NFT_CALL -f -' not in result.stderr
        if fault=='nft':
            assert 'lc_missing_chain' in (output/(label+'.nft')).read_text()
        if fault=='none': assert 'NFT_CALL -f -' not in result.stderr
        clean(); receipts.append(label+' leaves no owned kernel rules/routes/table')

    # Record a real success-path probe separately from the rollback result.
    probe=service('tproxy-probe','lc_rules_up','19099','192.0.2.7','203.0.113.7','19098')
    installed=probe.returncode==0
    unsupported_socket='socket transparent' in probe.stderr and 'No such file or directory' in probe.stderr
    if installed:
        assert len([r for r in rules([]) if marked(r,0x1000000)])==1
        assert routes([],104)
        run(nft,'list','table','inet','lite_client')
    else:
        clean()
    down('final-stop')
    (output/'foreign-after.json').write_text(json.dumps(foreign(),indent=2)+'\n')
    report=dict(validated=installed or not args.require_tproxy,rollback_validated=True,
                tproxy_installation_validated=installed,mode='full' if args.require_tproxy else 'rollback',
                unsupported_socket_expression=unsupported_socket,probe_returncode=probe.returncode,
                kernel=os.uname().release,ip_version=run(ip,'-Version').stdout.strip(),
                nft_version=run(nft,'--version').stdout.strip(),cases=receipts,
                scope='real isolated Linux kernel rules/routes/nft; route/nft faults injected at command boundary; no traffic/procd/device qualification')
    (output/'analysis.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if args.require_tproxy and not installed:
        raise SystemExit(77 if unsupported_socket else 1)


if __name__=='__main__': main()

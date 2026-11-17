"""Boot pinned OpenWrt in QEMU TCG and qualify successful rule installation.

The guest has no disks or network adapters. Kernel modules stay in the guest;
no KVM, host NET_ADMIN, SSH, package scripts or signing keys are required.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_inputs(manifest,cache,fetch=False):
    if fetch: cache.mkdir(parents=True,exist_ok=True)
    for entry in manifest['files']:
        name=entry['name']
        if PurePosixPath(name).name!=name: raise RuntimeError('unsafe VM input name')
        path=cache/name
        if fetch and not path.exists():
            url=manifest[entry['location']+'_base']+entry.get('path','')+name
            partial=path.with_suffix(path.suffix+'.part')
            with urllib.request.urlopen(url,timeout=60) as response,partial.open('wb') as output:
                shutil.copyfileobj(response,output)
            if digest(partial)!=entry['sha256']: raise RuntimeError('download checksum mismatch: '+name)
            partial.replace(path)
        if not path.is_file() or digest(path)!=entry['sha256']:
            raise RuntimeError('missing or mismatched pinned input: '+name)


def unpack_factory(root,cache,manifest):
    root.mkdir()
    rootfs=next(e for e in manifest['files'] if e['role']=='rootfs')
    # Factory absolute system symlinks are intentional; GNU tar refuses member
    # traversal through symlink parents. The input must already be checksum verified.
    with tarfile.open(cache/rootfs['name']) as archive:
        for member in archive:
            name=PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts: raise RuntimeError('unsafe rootfs member')
    subprocess.run(['tar','-xzf',str(cache/rootfs['name']),'-C',str(root)],check=True)


def pack_root(root,path):
    if not (root/'dev/console').exists():
        os.mknod(root/'dev/console',stat.S_IFCHR|0o600,os.makedev(5,1))
    with path.open('wb') as archive:
        find=subprocess.Popen(['find','.','-print0'],cwd=root,stdout=subprocess.PIPE)
        cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--quiet'],cwd=root,stdin=find.stdout,stdout=subprocess.PIPE)
        find.stdout.close()
        gzip=subprocess.Popen(['gzip','-n'],stdin=cpio.stdout,stdout=archive)
        cpio.stdout.close()
        codes=[gzip.wait(),cpio.wait(),find.wait()]
        if any(codes): raise RuntimeError(f'initramfs producers failed: {codes}')
    path.chmod(0o600)


def boot(manifest,cache,output,memory=256,timeout=120):
    kernel=next(e for e in manifest['files'] if e['role']=='kernel')
    command=['qemu-system-x86_64','-machine','accel=tcg','-cpu','qemu64','-m',str(memory),'-smp','1',
             '-display','none','-monitor','none','-serial','stdio','-nic','none','-no-reboot',
             '-kernel',str(cache/kernel['name']),'-initrd',str(output/'root.cpio.gz'),
             '-append','console=ttyS0 rdinit=/lc-init panic=-1']
    with (output/'console.log').open('wb') as log:
        subprocess.run(command,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=timeout)
    return (output/'console.log').read_text(errors='replace')


def analyze(states):
    expected=['baseline','tcp','tcp-clean','tcp-udp','repeat','external','all-clean','nft-failure']
    assert list(states)==expected,list(states)

    def marked(rule,mark):
        value=rule.get('fwmark',0)
        return (int(value,0) if isinstance(value,str) else value)==mark

    def foreign(state):
        return {**{k:[r for r in state[k] if marked(r,0x50505)] for k in ('rules4','rules6')},
                **{k:[r for r in state[k] if str(r.get('table'))=='105'] for k in ('routes4','routes6')},
                'nft':[item for item in state['nft']['nftables']
                       if any(isinstance(v,dict) and (v.get('table')=='lc_vm_foreign' or
                              (k=='table' and v.get('name')=='lc_vm_foreign')) for k,v in item.items())]}

    baseline=foreign(states['baseline'])
    assert baseline['rules4'] and baseline['rules6'] and baseline['routes4'] and baseline['routes6'] and baseline['nft']
    for label,state in states.items():
        assert foreign(state)==baseline,(label,'unrelated state changed')
        rules4=[r for r in state['rules4'] if marked(r,0x1000000)]
        assert not any(marked(r,0x1000000) for r in state['rules6']),label
        routes=[r for r in state['routes4'] if str(r.get('table'))=='104']
        owned=[item for item in state['nft']['nftables']
               if any(isinstance(v,dict) and (v.get('table')=='lite_client' or
                      (k=='table' and v.get('name')=='lite_client')) for k,v in item.items())]
        if label in ('baseline','tcp-clean','all-clean','nft-failure'):
            assert not rules4 and not routes and not owned,(label,'owned state remains')
            assert not any(str(r.get('table'))=='104' for r in state['routes6']),label
            continue
        assert len(rules4)==1 and str(rules4[0]['table'])=='104',label
        assert len(routes)==1 and routes[0]['type']=='local' and routes[0]['dev']=='lo',label
        nft_rules=[item['rule'] for item in owned if 'rule' in item]
        expressions=[expr for rule in nft_rules for expr in rule['expr']]
        ports=[expr['tproxy']['port'] for expr in expressions if 'tproxy' in expr]
        assert sorted(ports)==([] if label=='external' else [19099] if label=='tcp' else [19098,19098,19099,19099]),label
        sockets=[e['match']['left']['socket'] for e in expressions
                 if 'match' in e and isinstance(e['match'].get('left'),dict) and 'socket' in e['match']['left']]
        assert len(sockets)==1 and all(s['key']=='transparent' for s in sockets),label
        marks=[expr['mangle'] for expr in expressions if 'mangle' in expr]
        assert len(marks)==len(sockets)+len(ports) and all(
            m['key']=={'meta':{'key':'mark'}} and m['value']=={'|':[{'meta':{'key':'mark'}},0x1000000]} for m in marks),label
        if label=='external':
            assert any(e.get('match',{}).get('left',{}).get('payload',{}).get('protocol')=='ip6'
                       and e['match']['right']=='2001:db8::7' for e in expressions),label
    return expected[1:]


def main():
    if not __debug__: raise RuntimeError('VM qualification requires Python assertions enabled')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--fetch-only',action='store_true')
    parser.add_argument('--apk-tool',type=Path)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--expected-release')
    args=parser.parse_args()
    here=Path(__file__).resolve().parent
    manifest=json.loads((here/'vm-inputs.json').read_text())
    if args.expected_release and args.expected_release!=manifest['release']:
        raise RuntimeError('VM input pins must match the requested OpenWrt release')
    cache=args.cache.resolve()
    verify_inputs(manifest,cache,args.fetch_only)
    if args.fetch_only:
        print(f"Verified {len(manifest['files'])} pinned VM inputs")
        return
    if args.apk_tool is None or args.output is None:
        parser.error('boot requires --apk-tool and --output')
    apk=args.apk_tool.resolve()
    if not apk.is_file(): raise FileNotFoundError(apk)
    output=args.output.resolve(); output.mkdir(parents=True,exist_ok=False)
    source=Path(os.environ.get('LC_INIT',str(here.parents[1]/'package/files/lite-client.init'))).resolve()
    source_bytes=source.read_bytes()
    source_paths={'init':source,'runner':Path(__file__).resolve(),'guest':here/'vm-guest.sh','manifest':here/'vm-inputs.json'}
    source_hashes={name:digest(path) for name,path in source_paths.items()}
    (output/'inputs.json').write_text(json.dumps(manifest,indent=2)+'\n')
    with tempfile.TemporaryDirectory(prefix='lc-openwrt-vm-') as work:
        root=Path(work)/'root'; unpack_factory(root,cache,manifest)
        with (output/'prepare.log').open('w') as log:
            for entry in manifest['files']:
                if entry['role']=='addon':
                    # File hashes were checked above; this decodes pinned APKs without
                    # adding keys or running the package installation scripts.
                    subprocess.run([str(apk),'extract','--allow-untrusted','--destination',str(root),str(cache/entry['name'])],
                                   stdout=log,stderr=subprocess.STDOUT,check=True)
        ip=root/'sbin/ip'
        if not ip.is_symlink(): raise RuntimeError('unexpected factory ip layout')
        ip.unlink(); ip.symlink_to('../usr/libexec/ip-full')
        (root/'opt').mkdir(exist_ok=True)
        (root/'opt/lite-client.init').write_bytes(source_bytes)
        shutil.copyfile(here/'vm-guest.sh',root/'lc-init'); (root/'lc-init').chmod(0o755)
        pack_root(root,output/'root.cpio.gz')
    console=boot(manifest,cache,output)
    results=re.findall(r'^LC_VM_RESULT=(\d+)\s*$',console,re.M)
    if results!=['0']: raise RuntimeError('guest did not report success; see console.log')
    if re.findall(r'^LC_VM_KERNEL (\S+)',console,re.M)!=[manifest['kernel']]:
        raise RuntimeError('guest kernel differs from module pins')
    states={}
    for label,encoded in re.findall(r'^LC_VM_STATE (\S+) ([0-9a-f]+)\s*$',console,re.M):
        if label in states: raise RuntimeError('duplicate guest state: '+label)
        states[label]=json.loads(bytes.fromhex(encoded))
    cases=analyze(states)
    if source.read_bytes()!=source_bytes: raise RuntimeError('init source changed during VM qualification')
    if any(digest(path)!=source_hashes[name] for name,path in source_paths.items()):
        raise RuntimeError('qualification source changed during VM execution')
    for entry in manifest['files']:
        if digest(cache/entry['name'])!=entry['sha256']: raise RuntimeError('VM inputs changed during qualification')
    (output/'states.json').write_text(json.dumps(states,indent=2)+'\n')
    report=dict(validated=True,tproxy_installation_validated=True,release=manifest['release'],kernel=manifest['kernel'],
                cases=cases,init_sha256=hashlib.sha256(source_bytes).hexdigest(),
                source_sha256=source_hashes,
                scope='QEMU TCG x86 OpenWrt guest; real kernel/modules/ip-full/nft; no traffic, daemon, hardware, performance or device installation qualification')
    (output/'analysis.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__': main()

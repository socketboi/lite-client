"""Freeze local x86 SDK APKs and disposable test identities for the service VM.

The old fixture is a controlled package, not a historical release: it carries the
actual REALITY-only executable under the full-variant name. Upgrading to the
actual full APK must replace that running executable, not just the file on disk.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    if not __debug__: raise RuntimeError('qualification requires assertions enabled')
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('sdk','output','peer','xray'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    sdk=args.sdk.resolve(); output=args.output.resolve()
    output.mkdir(parents=True,exist_ok=False); output.chmod(0o700)
    apk=sdk/'staging_dir/host/bin/apk'
    source=Path(__file__).resolve().parents[2]

    def run(*command):
        result=subprocess.run([str(c) for c in command],check=True,capture_output=True,text=True,timeout=120)
        return result.stdout

    version=run(args.xray,'version').splitlines()[0]
    assert version.startswith('Xray 26.10.31 ') and 'go1.27.3 linux/amd64' in version,version
    for name,path in (('peer',args.peer),('xray',args.xray)):
        shutil.copyfile(path,output/name); (output/name).chmod(0o755)
    run(output/'peer','setup',output/'fixture')
    for path in sorted((output/'fixture').iterdir()):
        shutil.move(path,output/path.name)
    (output/'fixture').rmdir()
    metas={}
    with tempfile.TemporaryDirectory(prefix='lc-service-apk-') as work:
        work=Path(work)
        stages={}
        for name in ('lite-client','lite-client-hysteria'):
            packages=list((sdk/'bin').rglob(name+'-0.1.0-r2.apk'))
            assert len(packages)==1,(name,packages)
            package=output/packages[0].name; shutil.copyfile(packages[0],package)
            metadata=run(apk,'adbdump',package)
            assert re.search(r'^  arch: x86_64$',metadata,re.M),'requires the x86 SDK packages'
            assert re.search(r'^  name: '+re.escape(name)+r'$',metadata,re.M),name
            stages[name]=work/name; stages[name].mkdir()
            run(apk,'extract','--allow-untrusted','--destination',stages[name],package)
            assert (stages[name]/'etc/init.d/lite-client').read_bytes()==(source/'package/files/lite-client.init').read_bytes()
            assert (stages[name]/'etc/lite-client/fingerprint.fpt').read_bytes()==(source/'package/files/fingerprint.fpt').read_bytes()
            metas[name]=metadata
        old=stages['lite-client-hysteria']
        shutil.copyfile(stages['lite-client']/'usr/sbin/lc-tunnel',old/'usr/sbin/lc-tunnel')
        # Extract the exact SDK-generated hooks from the actual package metadata.
        scripts={}; current=None
        for line in metas['lite-client-hysteria'].split('scripts:\n',1)[1].splitlines():
            match=re.fullmatch(r'  ([a-z-]+): \|',line)
            if match:
                current=match[1]; scripts[current]=[]
            elif line.startswith('    ') and current:
                scripts[current].append(line[4:])
            else:
                current=None
        assert set(scripts)=={'post-install','post-upgrade','pre-deinstall'},scripts.keys()
        depends=metas['lite-client-hysteria'].split('  depends:',1)[1].split('\n  provides:',1)[0].split('\npaths:',1)[0]
        dependencies=re.findall(r'^    - (.+)$',depends,re.M)
        assert dependencies and 'libc' in dependencies,dependencies
        command=[apk,'mkpkg','--info','name:lite-client-hysteria','--info','version:0.0.9-r1',
                 '--info','arch:x86_64','--info','license:MPL-2.0','--info','depends:'+' '.join(dependencies),
                 '--files',old,'--output',output/'old-fixture.apk']
        for name,lines in scripts.items():
            path=work/(name+'.sh'); path.write_text('\n'.join(lines)+'\n')
            command+=['--script',name+':'+str(path)]
        run(*command)
        old_hash=hashlib.sha256((old/'usr/sbin/lc-tunnel').read_bytes()).hexdigest()
        full=work/'full-check'; full.mkdir()
        run(apk,'extract','--allow-untrusted','--destination',full,output/'lite-client-hysteria-0.1.0-r2.apk')
        new_hash=hashlib.sha256((full/'usr/sbin/lc-tunnel').read_bytes()).hexdigest()
        assert old_hash!=new_hash,'upgrade fixture must change executable bytes'
    files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.is_file()}
    plan=dict(schema='service-vm-bundle-v1',xray_version=version,
              init_sha256=hashlib.sha256((source/'package/files/lite-client.init').read_bytes()).hexdigest(),
              old_executable_sha256=old_hash,
              new_executable_sha256=new_hash,files=files,
              scope='disposable local identities; actual x86 SDK packages; controlled older fixture uses real REALITY-only executable')
    (output/'bundle.json').write_text(json.dumps(plan,indent=2)+'\n')
    print('Frozen service bundle; credentials retained privately, executable identities differ')


if __name__=='__main__': main()

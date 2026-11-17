"""Qualify real SDK APKs in disposable roots, with package scripts/network disabled.

Run explicitly after make package; dependencies come from the SDK's local APKs.
The old-version fixture exercises package-manager preservation, not historical
client compatibility. No keys are generated and nothing is installed on a device.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def package_version(source, build=None):
    recipe=(source/'package/release.mk').read_text()
    fields=[re.findall(r'^'+key+r':=([0-9.]+)$',recipe,re.M) for key in ('LC_PACKAGE_BASE_VERSION','LC_PACKAGE_RELEASE')]
    if any(len(values)!=1 for values in fields):
        raise ValueError('package recipe must declare one numeric version and release')
    if build is not None and not re.fullmatch(r'[1-9][0-9]*',build):
        raise ValueError('package build must be a positive pipeline number')
    return fields[0][0]+('_p'+build if build else '')+'-r'+fields[1][0]


def sdk_target(sdk):
    config=(sdk/'.config').read_text()
    found=re.findall(r'^CONFIG_TARGET_ARCH_PACKAGES="([^"]+)"$',config,re.M)
    if len(found)!=1:
        raise AssertionError('SDK must declare exactly one package architecture')
    emulators={'mipsel_24kc':'qemu-mipsel','aarch64_cortex-a53':'qemu-aarch64'}
    if found[0] not in emulators:
        raise AssertionError('unsupported SDK package architecture: '+found[0])
    return found[0],emulators[found[0]]


def main():
    if not __debug__: raise RuntimeError('qualification requires assertions enabled')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--expected-version',help='source revision explicitly stamped by an archive build')
    parser.add_argument('--package-build')
    args=parser.parse_args()
    sdk=args.sdk.resolve(); output=args.output.resolve()
    arch,emulator=sdk_target(sdk)
    output.mkdir(parents=True,exist_ok=False)
    apk=sdk/'staging_dir/host/bin/apk'
    source=Path(__file__).resolve().parents[2]
    pkg_version=package_version(source,args.package_build)
    receipts=[]

    def run(*command,expected=0,timeout=120):
        value=subprocess.run([str(c) for c in command],capture_output=True,text=True,timeout=timeout)
        with (output/'commands.log').open('a') as log:
            log.write(' '.join(map(str,command))+'\n'+value.stdout+value.stderr+'\n')
        if value.returncode!=expected:
            raise RuntimeError(f'command exited {value.returncode}: {command[:3]}; see commands.log')
        return value.stdout

    expected_version=args.expected_version or run('git','-C',source,'describe','--always','--dirty','--tags','--abbrev=12').strip()
    if not expected_version or expected_version=='unknown':
        raise AssertionError('package qualification requires an identified source checkout')

    # A flat local repository makes all real SDK dependency packages available offline.
    repo=output/'repository'; repo.mkdir()
    for package in sorted((sdk/'bin').rglob('*.apk')):
        link=repo/package.name
        if not link.exists(): link.symlink_to(package)
    index=repo/'packages.adb'
    run(apk,'mkndx','--allow-untrusted','--output',index,*sorted(repo.glob('*.apk')))

    for name in ('lite-client','lite-client-hysteria'):
        packages=list(repo.glob(name+'-'+pkg_version+'.apk'))
        if len(packages)!=1: raise AssertionError(f'expected one current {name} APK: {packages}')
        package=output/packages[0].name
        shutil.copyfile(packages[0],package)
        metadata=run(apk,'adbdump',package)
        (output/(name+'.metadata')).write_text(metadata)
        for field,value in (('name',name),('version',pkg_version),('license','MPL-2.0'),('arch',arch)):
            assert re.search(r'^  '+field+': '+re.escape(value)+r'$',metadata,re.M),(field,value)
        assert '!'+('lite-client-hysteria' if name=='lite-client' else 'lite-client') in metadata
        stage=output/(name+'-payload'); stage.mkdir()
        run(apk,'extract','--allow-untrusted','--destination',stage,package)
        conf=(stage/'lib/apk/packages'/(name+'.conffiles')).read_text().split()
        expected={'/etc/config/lite-client','/etc/lite-client/uuid','/etc/lite-client/auth','/etc/lite-client/obfs'}
        assert set(conf)==expected
        keep=(stage/'lib/upgrade/keep.d'/name).read_text().split()
        assert set(keep)==expected-{'/etc/config/lite-client'}
        static=(stage/'lib/apk/packages'/(name+'.conffiles_static')).read_text().splitlines()
        assert len(static)==1 and static[0].split()[0]=='/etc/config/lite-client'
        assert (stage/'etc/init.d/lite-client').read_bytes()==(source/'package/files/lite-client.init').read_bytes()
        assert (stage/'etc/lite-client/fingerprint.fpt').read_bytes()==(source/'package/files/fingerprint.fpt').read_bytes()
        (output/(name+'.payload.json')).write_text(json.dumps({
            '/'+path:hashlib.sha256((stage/path).read_bytes()).hexdigest()
            for path in ('usr/sbin/lc-tunnel','etc/init.d/lite-client','etc/lite-client/fingerprint.fpt')
        })+'\n')

        # Use the real APK first, so dependency resolution is checked without fixtures.
        root=output/(name+'-root'); root.mkdir()
        base=[apk,'--root',root,'--arch',arch,'--allow-untrusted',
              '--no-network','--no-scripts','--no-cache','--repository',index]
        if os.geteuid()!=0: base.append('--usermode')
        run(*base,'add','--initdb',package)
        # Downgrade to a deliberately old payload, then exercise a real version upgrade.
        fixture=output/(name+'-old'); shutil.copytree(stage,fixture)
        (fixture/'usr/sbin/lc-tunnel').write_text('old binary fixture\n')
        (fixture/'etc/init.d/lite-client').write_text('# old init fixture\n')
        (fixture/'etc/config/lite-client').write_text('# old default fixture\n')
        old=output/(name+'-0.0.9-r1.apk')
        run(apk,'mkpkg','--info','name:'+name,'--info','version:0.0.9-r1',
            '--info','arch:'+arch,'--files',fixture,'--output',old)
        run(*base,'add',old)
        config=root/'etc/config/lite-client'; config.write_text("config tunnel 'main'\n\toption enabled '0'\n# owner fixture\n")
        secrets={}
        for entry in ('uuid','auth','obfs'):
            path=root/'etc/lite-client'/entry
            value='00000000-0000-4000-8000-000000000001' if entry=='uuid' else 'fixture-'+entry
            path.write_text(value+'\n'); path.chmod(0o600)
            secrets[entry]=path.read_bytes()
        owned_config=config.read_bytes()
        run(*base,'add',package)
        assert config.read_bytes()==owned_config
        assert (root/'etc/config/lite-client.apk-new').read_bytes()==(stage/'etc/config/lite-client').read_bytes()
        for entry,data in secrets.items():
            path=root/'etc/lite-client'/entry
            assert path.read_bytes()==data and path.stat().st_mode & 0o777==0o600
        for entry in ('usr/sbin/lc-tunnel','etc/init.d/lite-client','etc/lite-client/fingerprint.fpt'):
            assert (root/entry).read_bytes()==(stage/entry).read_bytes(),entry
        assert (root/'etc/lite-client').stat().st_mode & 0o777==0o700
        assert config.stat().st_mode & 0o777==0o600
        # Run the actual packaged executable with its installed dependency libraries.
        sysroot=root
        planes=run(emulator,'-L',sysroot,root/'usr/sbin/lc-tunnel','--planes')
        assert ('hysteria' in planes)==(name=='lite-client-hysteria')
        version=run(emulator,'-L',sysroot,root/'usr/sbin/lc-tunnel','--version').strip()
        assert version==expected_version,(version,expected_version)
        command=[emulator,'-L',sysroot,root/'usr/sbin/lc-tunnel']
        run(*command,root/'etc/lite-client/fingerprint.fpt','offline.invalid','443',
            'config.test','00'*32,'0123abcd','@'+str(root/'etc/lite-client/uuid'),
            '19600','-w','4','--check-config')
        # Exercise the actual target open/fstat ABI, including a FIFO whose writer
        # would let a blocking open complete but leave fread waiting forever.
        table=root/'etc/lite-client/fingerprint.fpt'
        saved=table.read_bytes(); mode=table.stat().st_mode & 0o777
        table.unlink(); os.mkfifo(table,0o600)
        try:
            arguments=[table,'offline.invalid','443','config.test','00'*32,'0123abcd',
                       '@'+str(root/'etc/lite-client/uuid'),'19600','--check-config']
            run(*command,*arguments,expected=2,timeout=5)
            writer=os.open(table,os.O_RDWR|os.O_NONBLOCK)
            try:
                run(*command,*arguments,expected=2,timeout=5)
            finally:
                os.close(writer)
        finally:
            table.unlink(); table.write_bytes(saved); table.chmod(mode)
        assert table.read_bytes()==saved and table.stat().st_mode & 0o777==mode
        if name=='lite-client-hysteria':
            run(*command,'-H','offline.invalid','443','config.test',
                '@'+str(root/'etc/lite-client/auth'),'-','19600','-p','-','--check-config')
        if name=='lite-client':
            # Replace an installed, explicitly requested base package in one
            # solver transaction; retain every owner configuration and secret.
            full=next(repo.glob('lite-client-hysteria-'+pkg_version+'.apk'))
            run(*base,'add','--simulate',full,'!lite-client')
            assert (root/'usr/sbin/lc-tunnel').read_bytes()==(stage/'usr/sbin/lc-tunnel').read_bytes()
            run(*base,'add',full,'!lite-client')
            assert config.read_bytes()==owned_config
            for entry,data in secrets.items():
                path=root/'etc/lite-client'/entry
                assert path.read_bytes()==data and path.stat().st_mode & 0o777==0o600
            promoted=run(emulator,'-L',root,root/'usr/sbin/lc-tunnel','--planes')
            assert 'hysteria' in promoted
            run(apk,'--root',root,'--arch',arch,'info','--exists','lite-client-hysteria')
            run(apk,'--root',root,'--arch',arch,'info','--exists','lite-client',expected=1)
        receipts.append(dict(package=name,sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
                             installed_upgrade=True,credential_keep=keep,planes=planes.strip(),version=version,
                             fingerprint_fifo_refused=True))
    (output/'analysis.json').write_text(json.dumps(dict(validated=True,architecture=arch,source_version=expected_version,variants=receipts,
        scope='real offline APK install/fixture-version upgrade; scripts disabled; target planes under qemu; no device installation'),indent=2)+'\n')
    print((output/'analysis.json').read_text())


if __name__=='__main__': main()

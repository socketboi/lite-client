"""Inspect real 24.10 SDK IPKs and execute their binaries under QEMU.

This is payload qualification, not an opkg upgrade or device lifecycle test.
No package scripts are executed and no device is changed.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import tarfile

from check_apk import package_version, sdk_target


def main():
    if not __debug__:
        raise RuntimeError('qualification requires assertions enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-version', required=True)
    parser.add_argument('--package-build')
    args = parser.parse_args()
    if not args.expected_version or args.expected_version == 'unknown':
        raise ValueError('an identified source revision is required')
    sdk, output = args.sdk.resolve(), args.output.resolve()
    arch, emulator = sdk_target(sdk)
    roots = list((sdk / 'staging_dir').glob('target-*/root-*'))
    if len(roots) != 1:
        raise ValueError('expected exactly one SDK target root')
    source = Path(__file__).resolve().parents[2]
    version = package_version(source, args.package_build)
    output.mkdir(parents=True, exist_ok=False)
    credentials = {'/etc/lite-client/' + name for name in ('uuid', 'auth', 'obfs')}
    configuration = {'/etc/config/lite-client'}
    receipts = []
    for name, planes in (('lite-client', ['reality']),
                         ('lite-client-hysteria', ['reality', 'hysteria'])):
        matches = list((sdk / 'bin').rglob(name + '_' + version + '_' + arch + '.ipk'))
        if len(matches) != 1:
            raise ValueError('expected one current IPK for ' + name)
        package = output / matches[0].name
        package.write_bytes(matches[0].read_bytes())
        stage = output / name
        stage.mkdir()
        with tarfile.open(package) as archive:
            assert archive.extractfile('./debian-binary').read() == b'2.0\n'
            with tarfile.open(fileobj=io.BytesIO(archive.extractfile('./control.tar.gz').read())) as control:
                metadata = control.extractfile('./control').read().decode()
                conffiles = set(control.extractfile('./conffiles').read().decode().splitlines())
            with tarfile.open(fileobj=io.BytesIO(archive.extractfile('./data.tar.gz').read())) as payload:
                payload.extractall(stage, filter='data')
        for field, value in (('Package', name), ('Version', version),
                             ('Architecture', arch), ('License', 'MPL-2.0')):
            assert re.search(r'^' + field + ': ' + re.escape(value) + r'$', metadata, re.M)
        opposite = 'lite-client-hysteria' if name == 'lite-client' else 'lite-client'
        assert re.search(r'^Conflicts: ' + opposite + r'$', metadata, re.M)
        if name == 'lite-client-hysteria':
            assert re.search(r'^Replaces: lite-client$', metadata, re.M)
        assert configuration <= conffiles
        keep = set((stage / 'lib/upgrade/keep.d' / name).read_text().splitlines())
        assert configuration | credentials <= conffiles | keep
        for filename, original in (('etc/init.d/lite-client', 'lite-client.init'),
                                   ('etc/config/lite-client', 'lite-client.config'),
                                   ('etc/lite-client/fingerprint.fpt', 'fingerprint.fpt')):
            assert (stage / filename).read_bytes() == (source / 'package/files' / original).read_bytes()
        assert not any((stage / path.lstrip('/')).exists() for path in credentials)
        executable = stage / 'usr/sbin/lc-tunnel'
        (output / (name + '.payload.json')).write_text(json.dumps({
            '/' + path: hashlib.sha256((stage / path).read_bytes()).hexdigest()
            for path in ('usr/sbin/lc-tunnel', 'etc/init.d/lite-client', 'etc/lite-client/fingerprint.fpt')
        }) + '\n')
        binary = executable.read_bytes()
        assert binary[:6] == b'\x7fELF' + (b'\x01\x01' if arch == 'mipsel_24kc' else b'\x02\x01')
        assert struct.unpack_from('<H', binary, 18)[0] == (8 if arch == 'mipsel_24kc' else 183)
        assert executable.stat().st_mode & 0o111
        observations = {}
        for option in ('--version', '--planes'):
            result = subprocess.run([emulator, '-L', str(roots[0]), str(executable), option],
                                    capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, result.stderr
            observations[option] = result.stdout.strip()
        assert observations['--version'] == args.expected_version
        assert observations['--planes'].split() == planes
        receipts.append(dict(package=name, sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
                             binary_sha256=hashlib.sha256(binary).hexdigest(), bytes=package.stat().st_size,
                             version=observations['--version'], planes=planes, qemu_exit=0))
    report = dict(validated=True, architecture=arch, variants=receipts,
                  package_manager_lifecycle_executed=False,
                  scope='Actual IPK metadata, conffiles, payload and QEMU execution; no hooks or device installation')
    (output / 'analysis.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()

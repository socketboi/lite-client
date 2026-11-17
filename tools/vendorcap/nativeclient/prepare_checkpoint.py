"""Prepare fresh test-only credentials and exact checkpoint inputs, never a deployed config."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

from analyze_checkpoint import INPUTS, make_plan
from analyze_network import require
from checkpoint_process import digest
from native_checkpoint import freeze


def prepare(args):
    os.umask(0o077)
    root = args.directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root/'.gitignore').write_text('*\n')
    here = Path(__file__).resolve().parent
    for source in here.glob('*.py'):
        if not source.name.startswith('test_'):
            shutil.copyfile(source, root/source.name)
    shutil.copyfile(here/'native-device.sh', root/'native-device.sh')
    for source, target in ((args.lc, 'lc-tunnel.host'), (args.reference, 'reference.host'),
                           (args.destination, 'dest.host')):
        shutil.copyfile(source, root/target)
        (root/target).chmod(0o700)
    shutil.copyfile(args.source_root/'package/files/fingerprint.fpt', root/'fingerprint.fpt')
    manifest = []
    for base, patterns in (('src', ('*.c', '*.h')), ('vendor/Xray-core', ('*.go', 'go.mod', 'go.sum')),
                           ('tools/vendorcap/nativeclient/runner', ('*.go',)),
                           ('tools/vendorcap/nativeclient/encode', ('*.go',)),
                           ('tools/vendorcap/spiderredir/dest', ('*.go', 'go.mod', 'go.sum'))):
        for pattern in patterns:
            for source in sorted((args.source_root/base).rglob(pattern)):
                manifest.append(digest(source)+'  '+source.relative_to(args.source_root).as_posix()+'\n')
    for name in ('Makefile', 'docker/Dockerfile'):
        manifest.append(digest(args.source_root/name)+'  '+name+'\n')
    (root/'source.sha256').write_text(''.join(manifest))
    with (root/'prepare.log').open('w') as log:
        def openssl(*command):
            subprocess.run(['openssl', *command], cwd=root, check=True, stdout=log, stderr=log)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key',
                '-out', 'ca.pem', '-days', '2', '-subj', '/CN=checkpoint-test-only')
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key',
                '-out', 'leaf.csr', '-subj', '/CN=stand.example')
        (root/'leaf.ext').write_text('subjectAltName=DNS:stand.example\nextendedKeyUsage=serverAuth\n')
        openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                '-CAcreateserial', '-out', 'leaf.pem', '-days', '2', '-extfile', 'leaf.ext')
        openssl('verify', '-CAfile', 'ca.pem', 'leaf.pem')
    def keypair():
        result = subprocess.check_output([str(root/'reference.host'), 'x25519'], text=True)
        return dict(line.split(': ', 1) for line in result.splitlines() if ': ' in line)
    server_key = keypair()['PrivateKey']
    wrong_key = keypair()['Password (PublicKey)']
    host = '127.0.0.1' if args.mode == 'host' else args.advertised_host
    uuid = '00000000-0000-4000-8000-000000000001'
    client = dict(log=dict(loglevel='warning'), inbounds=[dict(listen='127.0.0.1', port=19990,
        protocol='dokodemo-door', settings=dict(address='127.0.0.1', port=18080, network='tcp'))],
        outbounds=[dict(protocol='vless', settings=dict(vnext=[dict(address=host, port=14480,
            users=[dict(id=uuid, flow='xtls-rprx-vision', encryption='none')])]),
            streamSettings=dict(network='raw', security='reality', realitySettings=dict(
                serverName='stand.example', fingerprint='firefox', publicKey=wrong_key,
                shortId='0123abcd')))])
    server = dict(log=dict(loglevel='warning'), inbounds=[dict(listen='127.0.0.1' if args.mode == 'host'
        else '0.0.0.0', port=14480, protocol='vless', settings=dict(clients=[dict(id=uuid,
        flow='xtls-rprx-vision')], decryption='none'), streamSettings=dict(network='raw',
        security='reality', realitySettings=dict(dest='127.0.0.1:18444', xver=0,
            serverNames=['stand.example'], privateKey=server_key, shortIds=['0123abcd'],
            minClientVer='0.0.0')))], outbounds=[dict(protocol='freedom')])
    for name, value in (('client.json', client), ('server.json', server)):
        (root/name).write_text(json.dumps(value, indent=2)+'\n')
    if args.mode == 'host':
        shutil.copyfile(here/'run_checkpoint.py', root/'driver.py')
        plan = make_plan({name: digest(root/name) for name in sorted(INPUTS)})
        with (root/'plan.json').open('x') as output:
            output.write(json.dumps(plan, indent=2)+'\n')
    else:
        require(all((args.native_lc, args.native_reference, args.encoder, args.device_json,
                     args.advertised_host)), 'native executable, encoder and device identity required')
        for source, target in ((args.native_lc, 'lc-tunnel.native'),
                               (args.native_reference, 'reference.native'), (args.device_json, 'device.json')):
            shutil.copyfile(source, root/target)
        subprocess.run([str(args.encoder.resolve()), str(root/'client.json'), str(root/'client.pb')], check=True)
        (root/'settings.json').write_text(json.dumps(dict(advertised_host=host,
            control_listen='0.0.0.0', control_port=args.control_port, control_token=secrets.token_hex(32),
            startup_wait_seconds=2, quiet_wait_seconds=6, max_seconds=1200), indent=2)+'\n')
        plan = freeze(root)
    return dict(schema=plan['schema'], inputs=len(plan['inputs']), plan_sha256=digest(root/'plan.json'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('host', 'native'))
    parser.add_argument('directory', type=Path)
    for name in ('source-root', 'lc', 'reference', 'destination'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('native-lc', 'native-reference', 'encoder', 'device-json'):
        parser.add_argument('--'+name, type=Path)
    parser.add_argument('--advertised-host')
    parser.add_argument('--control-port', type=int, default=19880)
    print(json.dumps(prepare(parser.parse_args()), indent=2))

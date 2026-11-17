"""Qualify actual APK hooks, procd, TPROXY traffic and backup/restore offline.

Two diskless OpenWrt boots have no external network adapters. The second boot
restores the first boot's sysupgrade configuration archive, not a flashed image.
All identities in the bundle are disposable local fixtures.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile

from run_vm import boot, digest, pack_root, unpack_factory, verify_inputs


def frames(console, prefix):
    result = {}
    for label, encoded in re.findall(r'^'+prefix+r' (\S+) ([0-9a-f]+)\s*$', console, re.M):
        if label in result:
            raise RuntimeError('duplicate frame: '+label)
        result[label] = bytes.fromhex(encoded)
    return result


def analyze(console, plan, restored=False):
    assert re.findall(r'^LC_SERVICE_RESULT=(\d+)\s*$', console, re.M) == ['0'], 'guest failed; inspect console.log'
    assert re.findall(r'^LC_SERVICE_PID1=(\S+)', console, re.M) == ['procd']
    states = {k: json.loads(v) for k, v in frames(console, 'LC_SERVICE_STATE').items()}
    expected = (['restored', 'stopped'] if restored else
                ['old-running', 'respawn', 'four-workers', 'four-respawn', 'upgraded', 'disabled',
                 'reenabled', 'invalid', 'config-recovered', 'tcp-only', 'worker-gap', 'tcp-recovered',
                 'udp-restored', 'occupied', 'bind-recovered', 'stopped'])
    assert list(states) == expected, list(states)
    inactive = {'disabled', 'invalid', 'stopped'}
    old = {'old-running', 'respawn', 'four-workers', 'four-respawn'}
    for label, state in states.items():
        nft = [v for item in state['nft']['nftables'] for v in item.values()
               if isinstance(v, dict) and (v.get('table') == 'lite_client' or v.get('name') == 'lite_client')]
        rules = [r for r in state['rules'] if str(r.get('table')) == '104']
        if label in inactive:
            assert not nft and not rules and not state['native'], (label, 'service residue')
            continue
        assert nft and len(rules) == 1, (label, 'interception missing')
        if label == 'occupied':
            continue  # Retry remains supervised and interception stays fail closed.
        sha = plan['old_executable_sha256' if label in old else 'new_executable_sha256']
        assert state['pid'] > 1 and state['live_sha256'] == state['disk_sha256'] == sha, label
        count = 1 if label in ('old-running', 'respawn', 'worker-gap') else 5
        assert len(state['native']) == count, (label, state['native'])
        assert all(p['sha256'] == sha for p in state['native']), (label, 'stale worker')
    if not restored:
        for before, after in [('old-running', 'respawn'), ('four-workers', 'four-respawn'), ('four-respawn', 'upgraded')]:
            assert states[before]['pid'] != states[after]['pid'], (before, after, 'process was not replaced')
        assert states['tcp-only']['pid'] == states['worker-gap']['pid'] == states['tcp-recovered']['pid']
    files = frames(console, 'LC_SERVICE_FILE')
    version = files['version'].decode().strip()
    assert version and version != 'unknown', 'package lost its checkout version'
    clients = [json.loads(line) for line in files['clients'].splitlines()]
    backend = [json.loads(line) for line in files['backend'].splitlines()]
    before_resume = [] if restored else [json.loads(line) for line in files['before-worker-resume'].splitlines()]
    assert backend[:len(before_resume)] == before_resume, 'backend snapshot is not a journal prefix'
    before_nonces = {r['nonce'] for r in before_resume}
    if not restored:
        completed_before_gap = {r['nonce'] for r in clients if r['result'] == 'echo' and
                                r['stage'] not in ('udp-restored', 'bind-recovered')}
        assert before_nonces == completed_before_gap, 'incomplete pre-recovery backend snapshot'
    positive = ['reference-control'] + (['restored'] if restored else
                ['old-running', 'respawn', 'four-workers', 'four-respawn', 'upgraded',
                 'reenabled', 'config-recovered', 'udp-restored', 'bind-recovered'])
    blocked = ['before-service', 'after-stop'] + ([] if restored else ['disabled', 'invalid', 'worker-gap', 'occupied'])
    assert len(clients) == 3 * (len(positive) + len(blocked))
    assert len({r['nonce'] for r in clients}) == len(clients), 'reused probe nonce'
    by_nonce = {r['nonce']: r for r in backend}
    assert len(by_nonce) == len(backend), 'duplicate backend receipt'
    for stage in positive + blocked:
        rows = [r for r in clients if r['stage'] == stage]
        assert sorted(r['kind'] for r in rows) == ['tcp', 'tls', 'udp'], stage
        for row in rows:
            assert re.fullmatch('[0-9a-f]{64}', row['nonce']) and re.fullmatch('[0-9a-f]{64}', row['sha256'])
            assert row['bytes'] == (1024 if row['kind'] == 'udp' else 65536)
            if stage in blocked:
                assert row['result'] == 'blocked', stage
                if stage == 'worker-gap':
                    assert row['nonce'] not in before_nonces, 'delivery before worker recovery'
                    # The shared TCP listener retains its kernel backlog. A client
                    # timeout does not discard bytes queued for a later consumer.
                    late = by_nonce.pop(row['nonce'], None)
                    if late is not None:
                        assert row['kind'] == 'tcp' and late['peer'] == '198.51.100.1'
                        assert late['result'] == 'echo' and late['stage'] == stage
                        assert all(row[k] == late[k] for k in ('kind', 'sha256', 'bytes'))
                else:
                    assert row['nonce'] not in by_nonce, stage
            else:
                receipt = by_nonce.pop(row['nonce'])
                assert row['result'] == receipt['result'] == 'echo'
                assert all(row[k] == receipt[k] for k in ('kind', 'sha256', 'bytes'))
                assert receipt['peer'] == '198.51.100.1', 'traffic bypassed the root proxy'
    assert not by_nonce, 'unaccounted backend traffic'
    assert b'198.51.100.9:80' in files['access'] and b'198.51.100.9:443' in files['access']
    return states, files, positive, blocked


def check_backup(blob, credentials):
    expected = {}
    for line in credentials.decode().splitlines():
        sha, name = line.split()
        assert re.fullmatch('[0-9a-f]{64}', sha)
        expected[name.lstrip('/')] = sha
    assert set(expected) == {'etc/config/lite-client', 'etc/lite-client/uuid', 'etc/lite-client/auth', 'etc/lite-client/obfs'}
    found = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            assert not path.is_absolute() and '..' not in path.parts, 'unsafe backup path'
            assert member.isfile() or member.isdir(), 'backup links/devices are not permitted'
            name = str(path)
            if name in expected:
                assert name not in found and member.isfile() and member.mode & 0o777 == 0o600, name
                found[name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    assert found == expected, 'backup lost configuration or secrets'


def main():
    if not __debug__:
        raise RuntimeError('qualification requires assertions enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--fetch-only', action='store_true')
    parser.add_argument('--expected-release')
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    manifest = json.loads((here/'vm-inputs.json').read_text())
    extra = json.loads((here/'vm-service-inputs.json').read_text())
    assert manifest['release'] == extra['release']
    if args.expected_release and args.expected_release != manifest['release']:
        raise RuntimeError('service VM pins differ from the requested OpenWrt release')
    manifest['files'] += extra['files']
    cache = args.cache.resolve()
    verify_inputs(manifest, cache, args.fetch_only)
    if args.fetch_only:
        print('Verified service VM input pins')
        return
    if args.bundle is None or args.output is None:
        parser.error('boot requires --bundle and --output')
    bundle = args.bundle.resolve()
    plan_hash = digest(bundle/'bundle.json')
    plan = json.loads((bundle/'bundle.json').read_text())
    assert plan['schema'] == 'service-vm-bundle-v1'
    assert plan['init_sha256'] == digest(here.parents[1]/'package/files/lite-client.init'), 'stale packaged init'
    assert set(plan['files']) == {p.name for p in bundle.iterdir()} - {'bundle.json'}
    for name, sha in plan['files'].items():
        assert PurePosixPath(name).name == name and not (bundle/name).is_symlink()
        assert digest(bundle/name) == sha, name
    sources = [Path(__file__).resolve(), here/'run_vm.py', here/'vm-service-init.sh', here/'vm-service-guest.sh',
               here/'service-peer.go', here/'prepare_service_vm.py', here/'vm-inputs.json',
               here/'vm-service-inputs.json', here.parents[1]/'package/files/lite-client.init']
    hashes = {str(p.relative_to(here.parents[1])): digest(p) for p in sources}
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    archive = None
    reports = []
    for phase in ('upgrade', 'restore'):
        case = output/phase
        case.mkdir()
        with tempfile.TemporaryDirectory(prefix='lc-service-vm-') as work:
            root = Path(work)/'root'
            unpack_factory(root, cache, manifest)
            opt = root/'opt'
            opt.mkdir(exist_ok=True)
            shutil.move(root/'etc/apk/repositories.d', opt/'factory-repositories.d')
            (opt/'inputs').mkdir()
            for entry in manifest['files']:
                if entry['role'] == 'addon':
                    shutil.copyfile(cache/entry['name'], opt/'inputs'/entry['name'])
            shutil.copytree(bundle, opt/'bundle')
            (opt/'vm-rc.d').mkdir()
            (root/'etc/inittab').write_text('::sysinit:/etc/init.d/rcS S boot\nconsole::respawnlate:/opt/service-run\n')
            for source, target in [('vm-service-init.sh', root/'lc-init'), ('vm-service-guest.sh', opt/'service-run')]:
                shutil.copyfile(here/source, target)
                target.chmod(0o755)
            if archive is not None:
                (opt/'restore.tgz').write_bytes(archive)
                (opt/'restore.tgz').chmod(0o600)
            pack_root(root, case/'root.cpio.gz')
        console = boot(manifest, cache, case, memory=512, timeout=300)
        assert re.findall(r'^LC_SERVICE_KERNEL (\S+)', console, re.M) == [manifest['kernel']]
        states, files, positive, blocked = analyze(console, plan, phase == 'restore')
        (case/'states.json').write_text(json.dumps(states, indent=2)+'\n')
        if phase == 'upgrade':
            archive = files['backup']
            credentials = files['credentials']
            check_backup(archive, credentials)
        else:
            assert files['final-credentials'] == credentials, 'restored bytes differ'
        reports.append(dict(phase=phase, positive=positive, blocked=blocked))
    verify_inputs(manifest, cache)
    assert all(digest(p) == hashes[str(p.relative_to(here.parents[1]))] for p in sources), 'sources changed'
    assert all(digest(bundle/name) == sha for name, sha in plan['files'].items()), 'bundle changed'
    assert digest(bundle/'bundle.json') == plan_hash, 'bundle manifest changed'
    report = dict(validated=True, release=manifest['release'], kernel=manifest['kernel'], cases=reports,
                  source_sha256=hashes, bundle=plan,
                  scope='Actual x86 APK hooks/procd/TPROXY TCP TLS UDP; sysupgrade configuration backup/restore across diskless boots; no firmware flashing, device or performance qualification')
    (output/'analysis.json').write_text(json.dumps(report, indent=2)+'\n')
    print('PASS: actual APK upgrade, procd recovery, TCP/TLS/UDP and fresh-boot configuration restore')


if __name__ == '__main__':
    main()

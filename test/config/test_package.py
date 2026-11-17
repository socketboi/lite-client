"""Stage the actual install recipes; no SDK build or package-manager installation."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from check_apk import sdk_target


class SDKTargetTests(unittest.TestCase):
    def test_emulator_must_match_the_sdk_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for arch,emulator in [('mipsel_24kc','qemu-mipsel'),('aarch64_cortex-a53','qemu-aarch64')]:
                (root/'.config').write_text('CONFIG_TARGET_ARCH_PACKAGES="'+arch+'"\n')
                self.assertEqual(sdk_target(root),(arch,emulator))
            for config in ('','CONFIG_TARGET_ARCH_PACKAGES="unsupported"\n',
                           'CONFIG_TARGET_ARCH_PACKAGES="mipsel_24kc"\n'*2):
                (root/'.config').write_text(config)
                with self.assertRaises(AssertionError):
                    sdk_target(root)


class PackagePayloadTests(unittest.TestCase):
    def test_qualification_refuses_optimized_python(self):
        for name in ('check_apk.py','check_service.py'):
            with self.subTest(checker=name):
                result=subprocess.run([sys.executable,'-O',str(Path('test/config')/name),'--help'],
                                      capture_output=True,text=True,timeout=5)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('qualification requires assertions enabled',result.stderr)

    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root=Path(cls.directory.name)
        cls.source=Path.cwd()
        sdk=cls.root/'sdk'; (sdk/'include').mkdir(parents=True)
        # Fixtures for the SDK install interface, also checked against the pinned SDK in review.
        (sdk/'rules.mk').write_text('INSTALL_DIR=install -d -m0755\nINSTALL_BIN=install -m0755\n'
                                   'INSTALL_DATA=install -m0644\nINSTALL_CONF=install -m0600\n')
        (sdk/'include/package.mk').write_text('define BuildPackage\nendef\n')
        makefile=cls.root/'stage.mk'
        recipe=Path(os.environ.get('LC_PACKAGE_MAKEFILE',str(cls.source/'package/Makefile'))).resolve()
        makefile.write_text('include '+str(recipe)+'\n'
            'stage:\n\t$(call Package/$(STAGE_PACKAGE)/install,$(STAGE_ROOT))\n'
            '\t@printf "%s\\n" "$(strip $(Package/lite-client/conffiles))" > $(STAGE_ROOT)/declared-conffiles\n')
        for variant,env,package in (('reality','LC_TUNNEL_HY0','lite-client'),
                                    ('hysteria','LC_TUNNEL_HY1','lite-client-hysteria')):
            build=cls.root/'build/lite-client-0.1.0'/variant/'build-openwrt'; build.mkdir(parents=True)
            shutil.copyfile(os.environ[env],build/'lc-tunnel')
            stage=cls.root/variant; stage.mkdir()
            result=subprocess.run(['make','-s','-C',str(cls.source/'package'),'-f',str(makefile),
                f'TOPDIR={sdk}',f'INCLUDE_DIR={sdk}/include',f'BUILD_DIR={cls.root}/build',
                f'BUILD_VARIANT={variant}',f'STAGE_PACKAGE={package}',f'STAGE_ROOT={stage}','stage'],
                capture_output=True,text=True,timeout=60)
            if result.returncode: raise AssertionError(result.stdout+result.stderr)

    def test_payload_permissions_and_managed_files(self):
        expected={'usr/sbin/lc-tunnel','etc/init.d/lite-client','etc/config/lite-client',
                  'etc/lite-client/fingerprint.fpt',
                  'usr/share/licenses/lite-client/LICENSE','usr/share/licenses/lite-client/THIRD_PARTY_NOTICES.md',
                  'declared-conffiles'}
        for variant in ('reality','hysteria'):
            with self.subTest(variant=variant):
                stage=self.root/variant
                self.assertEqual({p.relative_to(stage).as_posix() for p in stage.rglob('*') if p.is_file()},expected)
                self.assertEqual((stage/'etc/lite-client').stat().st_mode & 0o777,0o700)
                self.assertEqual((stage/'etc/config/lite-client').stat().st_mode & 0o777,0o600)
                self.assertEqual((stage/'etc/init.d/lite-client').read_bytes(),
                                 (self.source/'package/files/lite-client.init').read_bytes())
                self.assertEqual((stage/'etc/lite-client/fingerprint.fpt').read_bytes(),
                                 (self.source/'package/files/fingerprint.fpt').read_bytes())
                env='LC_TUNNEL_HY0' if variant=='reality' else 'LC_TUNNEL_HY1'
                self.assertEqual((stage/'usr/sbin/lc-tunnel').read_bytes(),Path(os.environ[env]).read_bytes())

    def test_conffiles_declare_late_credentials_without_the_managed_fingerprint(self):
        expected={'/etc/config/lite-client','/etc/lite-client/uuid','/etc/lite-client/auth','/etc/lite-client/obfs'}
        for variant in ('reality','hysteria'):
            with self.subTest(variant=variant):
                stage=self.root/variant
                declared=set((stage/'declared-conffiles').read_text().split())
                # Model APK's build-time static list before owner-created credentials exist.
                static={n for n in declared if (stage/n.lstrip('/')).is_file()}
                self.assertEqual(static,{'/etc/config/lite-client'})
                for name in ('uuid','auth','obfs'):
                    path=stage/'etc/lite-client'/name
                    path.write_text('fixture\n'); path.chmod(0o600)
                    self.addCleanup(path.unlink)
                self.assertEqual(declared,expected)
                # The SDK adds missing conffiles to keep.d in its later packaging step.
                preserved={n for n in declared if (stage/n.lstrip('/')).is_file()}
                self.assertEqual(preserved,expected)
                self.assertNotIn('/etc/lite-client/fingerprint.fpt',preserved)


if __name__=='__main__': unittest.main()

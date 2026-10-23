import importlib.util
import os
import sys
from pathlib import Path
import argparse
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('oneclick',Path(__file__).resolve().parents[1]/'scripts/oneclick.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def test_domain_rejects_injection_and_bad_urls(self):
        for bad in ['https://example.com','example.com:443','a;id.com','a.com\nroot','../a.com','-a.example.com','*.example.com','localhost','1.2.3.4']:
            with self.subTest(bad=bad),self.assertRaises(argparse.ArgumentTypeError):installer.domain(bad)
        self.assertEqual(installer.domain('Portal.Example.COM.'),'portal.example.com')

    def test_supported_operating_systems_are_explicit(self):
        self.assertTrue(installer.os_supported({'ID':'debian','VERSION_ID':'12'}))
        self.assertTrue(installer.os_supported({'ID':'ubuntu','VERSION_ID':'24.04'}))
        self.assertFalse(installer.os_supported({'ID':'debian','VERSION_ID':'13'}))
        self.assertFalse(installer.os_supported({'ID':'centos','VERSION_ID':'9'}))

    def test_atomic_write_preserves_existing_file_on_failed_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'state.json';installer.write_json(p,{'generation':1})
            with patch.object(installer.os,'replace',side_effect=OSError('disk failure')):
                with self.assertRaises(OSError):installer.write_json(p,{'generation':2})
            self.assertEqual(installer.read_json(p),{'generation':1})
            self.assertEqual(len(list(Path(directory).iterdir())),1)

    @unittest.skipUnless(os.name=='posix','Linux symlink replacement semantics')
    def test_rollback_restores_previous_binary_and_caddy_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);old=root/'old';old.mkdir();current=root/'current'
            # Link creation may need elevated Windows privileges; Linux CI executes this fully.
            try:current.symlink_to(root/'new',target_is_directory=True)
            except OSError:self.skipTest('Symlink privilege unavailable')
            instance=object.__new__(installer.Installer);instance.old_current=str(old);instance.stamp='test';instance.backup=root/'backup'
            with patch.object(installer,'ROOT',root),patch.object(installer.subprocess,'run') as run:
                instance.rollback()
            self.assertEqual(current.resolve(),old.resolve());self.assertEqual(run.call_count,2)

    def test_totp_reference_vector(self):
        with patch.object(installer.time,'time',return_value=59):
            self.assertEqual(installer.totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'),'287082')

    def test_external_command_timeout_is_bounded(self):
        with self.assertRaisesRegex(RuntimeError,'超过'):
            installer.run(sys.executable,'-c','import time; time.sleep(5)',timeout=0.1)

    def test_background_descendant_cannot_hold_command_output_pipe(self):
        result=installer.run(sys.executable,'-c','import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time;time.sleep(2)"]);print("done")',timeout=1)
        self.assertIn('done',result)


if __name__=='__main__':unittest.main()

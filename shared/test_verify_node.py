"""Check that the regtest launcher rejects a download before extraction."""
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest


class VerifyNodeDownloadTests(unittest.TestCase):
    def test_mismatched_archive_is_never_extracted(self):
        launcher = Path(__file__).with_name('verify_node.sh').resolve()
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            curl = directory / 'curl'
            curl.write_text('#!/bin/bash\nprintf %s "test archive bytes" > "${!#}"\n', encoding='ascii')
            curl.chmod(0o755)
            tar = directory / 'tar'
            tar.write_text('#!/bin/bash\ntouch "$VERIFY_NODE_TEST_EXTRACTED"\nexit 99\n', encoding='ascii')
            tar.chmod(0o755)
            extracted = directory / 'extracted'
            env = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}", LC_ALL='C',
                       VERIFY_NODE_TEST_EXTRACTED=str(extracted))
            result = subprocess.run(['bash', str(launcher)], env=env, cwd=directory,
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b'FAILED', result.stdout)
            self.assertFalse(extracted.exists())

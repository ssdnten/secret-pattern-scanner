from pathlib import Path
import tempfile
import unittest
from main import scan

class Tests(unittest.TestCase):
    def run_scan(self, data, name='demo.txt', **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,name).write_bytes(data)
            return scan(tmp, **kwargs)
    def test_redaction(self):
        result = self.run_scan(b'password="fictional-demo-value"')
        self.assertEqual(len(result['findings']),1)
        self.assertNotIn('fictional-demo-value', str(result))
    def test_marker(self): self.assertEqual(self.run_scan(b'-----BEGIN PRIVATE KEY-----')['findings'][0]['rule'],'private_key_marker')
    def test_binary(self): self.assertEqual(self.run_scan(b'\x00')['skipped'][0]['reason'],'binary_or_encoding')
    def test_size_limit(self): self.assertEqual(self.run_scan(b'abcdef',max_bytes=3)['skipped'][0]['reason'],'size_limit')
    def test_no_finding(self): self.assertEqual(self.run_scan(b'debug=false')['findings'],[])
    def test_ignored_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'.git').mkdir(); Path(tmp,'.git','x').write_text('password="fictional-value"')
            self.assertEqual(scan(tmp)['findings'],[])

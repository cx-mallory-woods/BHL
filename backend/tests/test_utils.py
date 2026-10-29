"""
Basic tests for utility functions
"""
import unittest
import sys
import os
import json
import tempfile
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.datetime_utils import get_utc_now, format_utc_datetime, get_utc_timestamp


class TestDateTimeUtils(unittest.TestCase):
    """Test datetime utility functions"""
    
    def test_get_utc_now(self):
        """Test get_utc_now returns datetime"""
        result = get_utc_now()
        self.assertIsInstance(result, datetime)
    
    def test_get_utc_timestamp(self):
        """Test get_utc_timestamp returns float"""
        result = get_utc_timestamp()
        self.assertIsInstance(result, float)
        self.assertGreater(result, 0)
    
    def test_format_utc_datetime_default(self):
        """Test format_utc_datetime with default (current time)"""
        result = format_utc_datetime()
        self.assertIsInstance(result, str)
        # ISO format should contain 'T'
        self.assertIn('T', result)
    
    def test_format_utc_datetime_with_value(self):
        """Test format_utc_datetime with specific datetime"""
        dt = datetime(2023, 12, 25, 15, 30, 45)
        result = format_utc_datetime(dt)
        self.assertIsInstance(result, str)
        self.assertIn('2023', result)
        self.assertIn('12', result)
        self.assertIn('25', result)


class TestStringUtils(unittest.TestCase):
    """Test basic string utilities"""
    
    def test_string_truncation_logic(self):
        """Test basic truncation logic"""
        text = "This is a very long text that should be truncated"
        max_length = 20
        
        if len(text) > max_length:
            truncated = text[:max_length] + '...'
        else:
            truncated = text
        
        self.assertEqual(len(truncated), 23)  # 20 + "..."
        self.assertTrue(truncated.endswith('...'))
    
    def test_file_size_calculation(self):
        """Test file size calculation logic"""
        # Test bytes
        size = 500
        self.assertLess(size, 1024)
        
        # Test KB
        size_kb = 1500
        kb_value = size_kb / 1024.0
        self.assertGreater(kb_value, 1.0)
        self.assertLess(kb_value, 1024.0)


class TestProcessPickleFile(unittest.TestCase):
    """Tests for process_pickle_file (CWE-502 remediation).

    The function was previously vulnerable to arbitrary-code-execution via
    pickle deserialization of untrusted data.  It now uses json.load, which
    carries no execution semantics.
    """

    def setUp(self):
        """Create a temporary directory for test files."""
        from utils.file_handler import process_pickle_file
        self.process_pickle_file = process_pickle_file
        self.tmp_dir = tempfile.mkdtemp()

    def _write_file(self, name, content, mode='w', encoding='utf-8'):
        path = os.path.join(self.tmp_dir, name)
        if mode == 'wb':
            with open(path, 'wb') as fh:
                fh.write(content)
        else:
            with open(path, mode, encoding=encoding) as fh:
                fh.write(content)
        return path

    # --- Positive cases: valid JSON is parsed correctly ---

    def test_dict_payload(self):
        """A JSON object file is deserialized to a Python dict."""
        path = self._write_file('data.json', json.dumps({'key': 'value', 'num': 42}))
        result = self.process_pickle_file(path)
        self.assertIsInstance(result, dict)
        self.assertEqual(result['key'], 'value')
        self.assertEqual(result['num'], 42)

    def test_list_payload(self):
        """A JSON array file is deserialized to a Python list."""
        path = self._write_file('list.json', json.dumps([1, 2, 3]))
        result = self.process_pickle_file(path)
        self.assertIsInstance(result, list)
        self.assertEqual(result, [1, 2, 3])

    def test_nested_structure(self):
        """Nested JSON structures are handled correctly."""
        payload = {'outer': {'inner': [1, 2, {'deep': True}]}}
        path = self._write_file('nested.json', json.dumps(payload))
        result = self.process_pickle_file(path)
        self.assertEqual(result['outer']['inner'][2]['deep'], True)

    def test_unicode_content(self):
        """Unicode content in JSON is preserved."""
        payload = {'msg': '中文测试'}  # Chinese characters
        path = self._write_file('unicode.json', json.dumps(payload, ensure_ascii=False))
        result = self.process_pickle_file(path)
        self.assertEqual(result['msg'], '中文测试')

    # --- Negative cases: malicious/invalid input is handled safely ---

    def test_invalid_json_returns_error_dict(self):
        """Non-JSON content returns an error dict instead of raising."""
        path = self._write_file('bad.txt', 'this is not json')
        result = self.process_pickle_file(path)
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    def test_pickle_payload_rejected(self):
        """A raw pickle bytestream (attack payload) is NOT deserialized as Python objects.

        An attacker-supplied pickle file must NOT result in the execution of
        __reduce__ or any other Python code.  The function must return an error
        dict, proving that json.load was used instead of pickle.load.
        """
        import pickle as _pickle

        class _Exploit:
            """Simulated malicious pickle payload that sets a flag if executed."""
            executed = False

            def __reduce__(self):
                # In a real attack this would spawn a shell; here we just set a flag.
                import os as _os
                return (setattr, (_Exploit, 'executed', True))

        raw_pickle = _pickle.dumps(_Exploit())
        path = self._write_file('malicious.pkl', raw_pickle, mode='wb')

        result = self.process_pickle_file(path)

        # The function must NOT have executed the pickle payload.
        self.assertFalse(
            _Exploit.executed,
            'Pickle __reduce__ was executed — the deserialization sink is still unsafe.',
        )
        # The function must return an error dict (JSON can't parse binary pickle data).
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    def test_missing_file_returns_error_dict(self):
        """A missing file path returns an error dict instead of raising."""
        result = self.process_pickle_file('/nonexistent/path/file.pkl')
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    def test_empty_json_object(self):
        """An empty JSON object is deserialized to an empty dict."""
        path = self._write_file('empty.json', '{}')
        result = self.process_pickle_file(path)
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {})

    def test_no_pickle_import_needed(self):
        """The file_handler module must not import pickle (CWE-502 prevention)."""
        import importlib
        import utils.file_handler as fh_module
        # Verify pickle is NOT in the module's namespace
        self.assertFalse(
            hasattr(fh_module, 'pickle'),
            'pickle is still imported in file_handler — the vulnerable import was not removed.',
        )


if __name__ == '__main__':
    unittest.main()


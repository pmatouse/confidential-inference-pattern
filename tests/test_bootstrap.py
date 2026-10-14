from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'components/confidential-storage-authority'))
from bootstrap import bootstrap,verify,verify_server
from authority import Authority

class BootstrapTests(unittest.TestCase):
    def test_server_cannot_switch_to_empty_database(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';bootstrap(state,'demo-1')
            config=Path(d)/'server.json'
            config.write_text(json.dumps({'database':str(state/'authority.db')}))
            verify_server(config,state,'demo-1')
            config.write_text(json.dumps({'database':str(state/'replacement.db')}))
            with self.assertRaises(ValueError):verify_server(config,state,'demo-1')
            self.assertFalse((state/'replacement.db').exists())
    def test_missing_initialization_history_is_not_recreated(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';bootstrap(state,'demo-1')
            with sqlite3.connect(state/'authority.db') as c:
                c.execute('DROP TABLE initialization_sources')
            with self.assertRaises(ValueError):bootstrap(state,'demo-1')
    def test_new_then_repeat_keeps_history(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';r=bootstrap(state,'demo-1')
            a=Authority(state/'authority.db');a.register('volume-1','a'*64,'b'*64,'kbs:///default/keys/data')
            self.assertEqual(bootstrap(state,'demo-1'),r)
            self.assertEqual(a.inspect('volume-1')['generation'],1)
    def test_missing_db_never_recreated(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';bootstrap(state,'demo-1');(state/'authority.db').unlink()
            with self.assertRaises(FileNotFoundError):bootstrap(state,'demo-1')
            self.assertFalse((state/'authority.db').exists())
    def test_partial_directory_not_fresh(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';state.mkdir(mode=0o700)
            with self.assertRaises(FileNotFoundError):bootstrap(state,'demo-1')
    def test_identity_change_refused(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';bootstrap(state,'demo-1')
            with self.assertRaises(ValueError):bootstrap(state,'demo-2')
    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/'retained';bootstrap(state,'demo-1');link=Path(d)/'alias';link.symlink_to(state)
            with self.assertRaises(ValueError):bootstrap(link,'demo-1')

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from common_relay.journal import Journal, RETENTION

class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'state.db';self.now=1000000
        self.j=Journal(self.path,'scope',lambda:self.now)
    def tearDown(self):self.j.close();self.tmp.cleanup()
    def prepare(self,id='id',data=b'hello'):
        return self.j.prepare(id,'bob',hashlib.sha256(data).hexdigest(),60,lambda expiry:'original-cipher')
    def test_restart_reuses_cipher_and_deadline(self):
        original=self.prepare();self.j.close();self.now+=30;self.j=Journal(self.path,'scope',lambda:self.now)
        self.assertEqual(self.prepare(),original)
        with self.assertRaises(ValueError):self.prepare(data=b'changed')
        self.j.complete('id');self.assertIsNone(self.prepare()[0])
        self.assertIsNone(self.j.db.execute('SELECT body FROM outbox').fetchone()[0])
        self.now+=RETENTION;self.j.cleanup();self.assertEqual(self.j.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0],0)
    def test_expiry_keeps_tombstone_then_purges(self):
        self.prepare();self.j.acknowledge('alice','in');self.assertTrue(self.j.contains('alice','in'))
        self.now+=60;self.j.cleanup()
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(self.j.db.execute('SELECT body,status FROM outbox').fetchone(),(None,'expired'))
        self.now+=RETENTION;self.j.cleanup();self.assertFalse(self.j.contains('alice','in'))
    def test_bounded_cleanup(self):
        for i in range(300):self.prepare(str(i))
        self.now+=60;self.j.cleanup()
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM outbox WHERE status='expired'").fetchone()[0],256)
        self.j.cleanup();self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM outbox WHERE status='pending'").fetchone()[0],0)
    def test_legacy_migration_preserves_but_does_not_replay(self):
        self.j.close();self.path.unlink();db=sqlite3.connect(self.path)
        db.execute('CREATE TABLE outbox(scope TEXT,id TEXT,recipient TEXT,digest TEXT,body TEXT,PRIMARY KEY(scope,id))')
        db.execute('CREATE TABLE received(scope TEXT,sender TEXT,id TEXT,PRIMARY KEY(scope,sender,id))')
        db.execute('INSERT INTO outbox VALUES(?,?,?,?,?)',('scope','id','bob',hashlib.sha256(b'hello').hexdigest(),'old'))
        db.execute('INSERT INTO received VALUES(?,?,?)',('scope','alice','in'));db.commit();db.close()
        self.j=Journal(self.path,'scope',lambda:self.now)
        self.assertTrue(self.j.contains('alice','in'));self.assertEqual(self.j.db.execute('SELECT body FROM outbox').fetchone()[0],'old')
        with self.assertRaises(ValueError):self.prepare()
        self.now+=RETENTION;self.j.cleanup();self.assertEqual(self.j.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0],0)

"""Durable offline delivery state. One owning client per state database."""
import os
import sqlite3
import time
from pathlib import Path

RETENTION = 7 * 86400

class Journal:
    def __init__(self, path, scope, clock=time.time):
        self.scope, self.clock = scope, clock
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(path)
        self.db.execute('CREATE TABLE IF NOT EXISTS received(scope TEXT,sender TEXT,id TEXT,PRIMARY KEY(scope,sender,id))')
        self.db.execute('CREATE TABLE IF NOT EXISTS outbox(scope TEXT,id TEXT,recipient TEXT,digest TEXT,body TEXT,PRIMARY KEY(scope,id))')
        now = int(clock())
        with self.db:
            for table, fields in {'received': {'purge': 'INTEGER'}, 'outbox': {'expires': 'INTEGER', 'purge': 'INTEGER', 'status': 'TEXT'}}.items():
                columns = {r[1] for r in self.db.execute('PRAGMA table_info('+table+')')}
                for name, kind in fields.items():
                    if name not in columns:
                        self.db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {kind}')
            self.db.execute('UPDATE received SET purge=? WHERE purge IS NULL', (now+RETENTION,))
            # Historical expiry is unknowable: retain bytes, but never renew/replay them.
            self.db.execute("UPDATE outbox SET expires=?,purge=?,status='legacy' WHERE expires IS NULL", (now,now+RETENTION))
        self.cleanup()

    def prepare(self, object_id, recipient, digest, ttl, seal):
        if not 1 <= ttl <= 86400:
            raise ValueError('Invalid TTL')
        now = int(self.clock())
        with self.db:
            row = self.db.execute('SELECT recipient,digest,body,expires,status FROM outbox WHERE scope=? AND id=?',(self.scope,object_id)).fetchone()
            if row:
                if row[0] != recipient or row[1] != digest:
                    raise ValueError('Message ID reused with different content')
                if row[4] == 'received':
                    return None, row[3]
                if row[4] != 'pending' or row[3] <= now:
                    raise ValueError('Message expired or legacy expiry unknown')
                return row[2], row[3]
            expires = now+ttl
            body = seal(expires)
            self.db.execute('INSERT INTO outbox(scope,id,recipient,digest,body,expires,purge,status) VALUES(?,?,?,?,?,?,?,?)',(self.scope,object_id,recipient,digest,body,expires,expires+RETENTION,'pending'))
            return body, expires

    def complete(self, object_id):
        with self.db:
            self.db.execute("UPDATE outbox SET body=NULL,status='received',purge=? WHERE scope=? AND id=?",(int(self.clock())+RETENTION,self.scope,object_id))

    def contains(self, sender, object_id):
        return self.db.execute('SELECT 1 FROM received WHERE scope=? AND sender=? AND id=? AND purge>?',(self.scope,sender,object_id,int(self.clock()))).fetchone() is not None

    def acknowledge(self, sender, object_id):
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO received(scope,sender,id,purge) VALUES(?,?,?,?)',(self.scope,sender,object_id,int(self.clock())+RETENTION))

    def cleanup(self, batch=256):
        now = int(self.clock())
        with self.db:
            self.db.execute("UPDATE outbox SET body=NULL,status='expired' WHERE rowid IN (SELECT rowid FROM outbox WHERE scope=? AND status='pending' AND expires<=? LIMIT ?)",(self.scope,now,batch))
            for table in ('outbox','received'):
                self.db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE scope=? AND purge<=? LIMIT ?)',(self.scope,now,batch))

    def close(self):
        self.db.close()

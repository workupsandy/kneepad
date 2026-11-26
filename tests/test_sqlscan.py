import unittest

from helpers import ROOT  # noqa: F401

from kneepad.sqlscan import scan_mongo, scan_redis, scan_sql

SQL_CASES = [
    ("DROP DATABASE prod;", ["drop-database"]),
    ("drop database prod", ["drop-database"]),
    ("DROP SCHEMA public CASCADE", ["drop-database"]),
    ("DROP KEYSPACE ks", ["drop-database"]),
    ("drop table users", ["drop-table"]),
    ("DROP TABLE IF EXISTS users CASCADE;", ["drop-table"]),
    ("TRUNCATE TABLE logs; SELECT 1", ["truncate"]),
    ("truncate logs", ["truncate"]),
    ("DELETE FROM users", ["delete-no-where"]),
    ("delete from users;", ["delete-no-where"]),
    ("DELETE FROM users WHERE id = 3", []),
    ("DELETE FROM users WHERE 1=1", ["delete-no-where"]),
    ("DELETE FROM users WHERE 1 = 1", ["delete-no-where"]),
    ("DELETE FROM users WHERE TRUE;", ["delete-no-where"]),
    ("DELETE FROM users WHERE 'a' = 'a'", ["delete-no-where"]),
    ("DELETE FROM t WHERE a = 1 OR 1=1", ["delete-no-where"]),
    ("DELETE FROM t WHERE a = 1 AND 1=1", []),
    ("DELETE FROM t WHERE (1=1)", ["delete-no-where"]),
    ("DELETE FROM users WHERE id IN (SELECT id FROM old WHERE x=1)", []),
    ("DELETE FROM users USING old WHERE users.id = old.id", []),
    ("DELETE FROM t LIMIT 5", ["delete-no-where"]),
    ("UPDATE users SET active = false", ["update-no-where"]),
    ("UPDATE users SET active = false WHERE id = 2", []),
    ("UPDATE users SET x = (SELECT max(y) FROM t WHERE z = 1)", ["update-no-where"]),
    ("UPDATE users SET a = 1 WHERE 1=1", ["update-no-where"]),
    ("ALTER TABLE t DROP COLUMN c", ["drop-column"]),
    ("ALTER TABLE t ADD COLUMN c int", []),
    ("DROP USER bob", ["drop-role"]),
    ("DROP ROLE bob", ["drop-role"]),
    ("DROP VIEW v", []),
    ("DROP INDEX i", []),
    ("DROP FUNCTION f()", []),
    ("select 1; delete from t; select 2", ["delete-no-where"]),
    ("INSERT INTO t VALUES ('a;b'); DROP TABLE t;", ["drop-table"]),
    ("WITH x AS (SELECT 1) DELETE FROM t", ["delete-no-where"]),
    # things that must NOT trigger
    ("SELECT 'DROP TABLE x;' FROM t", []),
    ("SELECT \"DROP TABLE\" FROM t", []),
    ("-- DROP TABLE x\nSELECT 1", []),
    ("# DROP TABLE x\nSELECT 1", []),
    ("/* DROP DATABASE x */ SELECT 1;", []),
    ("SELECT * FROM users", []),
    ("INSERT INTO t (a) VALUES ('DELETE FROM x')", []),
    ("CREATE TABLE drop_log (id int)", []),
    ("SELECT delete_flag FROM t", []),
    ("", []),
    ("   ", []),
    (";;;", []),
]


class TestSql(unittest.TestCase):
    def test_cases(self):
        bad = []
        for sql, expected in SQL_CASES:
            got = [k for k, _ in scan_sql(sql)]
            if got != expected:
                bad.append((sql, got, expected))
        self.assertFalse(bad, "\n".join(map(str, bad)))

    def test_dollar_quoted_bodies_are_opaque(self):
        # Documented limitation: code inside $$...$$ is treated as a string.
        self.assertEqual(scan_sql("DO $$ BEGIN DROP TABLE x; END $$;"), [])
        self.assertEqual([k for k, _ in scan_sql("DO $$ x $$; DROP TABLE y;")], ["drop-table"])

    def test_escaped_and_doubled_quotes(self):
        self.assertEqual(scan_sql("SELECT 'it''s; DROP TABLE x'"), [])
        self.assertEqual(scan_sql("SELECT 'a\\'; DROP TABLE x; --'"), [])

    def test_huge_input_is_linear(self):
        import time
        big = "SELECT '" + "x;" * 400_000 + "'"
        t = time.time()
        scan_sql(big)
        self.assertLess(time.time() - t, 3.0)
        t = time.time()
        scan_sql(("DELETE FROM t WHERE a = 1; " * 50_000))
        self.assertLess(time.time() - t, 5.0)


class TestMongo(unittest.TestCase):
    def test_cases(self):
        cases = [
            ("db.users.drop()", ["mongo-drop-collection"]),
            ("db.getCollection('x').drop()", ["mongo-drop-collection"]),
            ("db['users'].drop()", ["mongo-drop-collection"]),
            ("db.dropDatabase()", ["mongo-drop-database"]),
            ("client.drop_database('x')", ["mongo-drop-database"]),
            ("db.users.deleteMany({})", ["mongo-delete-all"]),
            ("db.users.deleteMany( { } )", ["mongo-delete-all"]),
            ("db.users.remove()", ["mongo-delete-all"]),
            ("db.users.remove({})", ["mongo-delete-all"]),
            ("coll.delete_many({})", ["mongo-delete-all"]),
            ("db.users.updateMany({}, {$set:{a:1}})", ["mongo-update-all"]),
            ("db.users.deleteMany({a:1})", []),
            ("db.users.find({})", []),
            ("db.users.updateMany({a:1}, {$set:{a:2}})", []),
            ("// db.users.drop()\ndb.users.find()", []),
            ("/* db.dropDatabase() */ db.users.find()", []),
            ("db.users.countDocuments({})", []),
        ]
        bad = [(t, [k for k, _ in scan_mongo(t)], e) for t, e in cases if [k for k, _ in scan_mongo(t)] != e]
        self.assertFalse(bad, bad)


class TestRedis(unittest.TestCase):
    def test_cases(self):
        for t, hit in [("FLUSHALL", 1), ("flushdb", 1), ("echo flushall", 1), ("-n 1 FLUSHDB", 1),
                       ("get flushallkey", 0), ("SET a 1", 0), ("flushall2", 0)]:
            self.assertEqual(len(scan_redis(t)), hit, t)


if __name__ == "__main__":
    unittest.main()

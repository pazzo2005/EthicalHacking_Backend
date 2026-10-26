const session = require("express-session");

class SQLiteSessionStore extends session.Store {
  constructor(db) {
    super();
    this.db = db;
    this.getStatement = db.prepare("SELECT sess FROM sessions WHERE sid = ? AND expire > ?");
    this.setStatement = db.prepare(`
      INSERT INTO sessions (sid, sess, expire) VALUES (?, ?, ?)
      ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expire = excluded.expire
    `);
    this.destroyStatement = db.prepare("DELETE FROM sessions WHERE sid = ?");
    this.touchStatement = db.prepare("UPDATE sessions SET expire = ? WHERE sid = ?");
    this.pruneStatement = db.prepare("DELETE FROM sessions WHERE expire <= ?");
    this.pruneTimer = setInterval(() => {
      try { this.pruneStatement.run(Date.now()); } catch (error) { this.emit("error", error); }
    }, 15 * 60 * 1000);
    this.pruneTimer.unref();
  }

  get(sid, callback) {
    try {
      const row = this.getStatement.get(sid, Date.now());
      callback(null, row ? JSON.parse(row.sess) : null);
    } catch (error) { callback(error); }
  }

  set(sid, sess, callback = () => {}) {
    try {
      const expiresAt = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 86400000;
      this.setStatement.run(sid, JSON.stringify(sess), expiresAt);
      callback(null);
    } catch (error) { callback(error); }
  }

  destroy(sid, callback = () => {}) {
    try { this.destroyStatement.run(sid); callback(null); }
    catch (error) { callback(error); }
  }

  touch(sid, sess, callback = () => {}) {
    try {
      const expiresAt = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 86400000;
      this.touchStatement.run(expiresAt, sid);
      callback(null);
    } catch (error) { callback(error); }
  }
}

module.exports = SQLiteSessionStore;

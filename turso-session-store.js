'use strict';

// Persistent express-session Store backed by Turso/libSQL.
const session = require('express-session');

class TursoSessionStore extends session.Store {
  constructor({ client, defaultTtlMs = 2 *60 * 60 * 1000 } = {}) {
    super();

    if (!client || typeof client.execute !== 'function') {
      throw new TypeError('TursoSessionStore requires a libSQL client');
    }

    if (!Number.isSafeInteger(defaultTtlMs) || defaultTtlMs <= 0) {
      throw new TypeError('defaultTtlMs must be a positive integer');
    }

    this.client = client;
    this.defaultTtlMs = defaultTtlMs;

    this.ready = Promise.resolve();
  }

  expiresAt(sess) {
    const expires = sess?.cookie?.expires;

    if (expires) {
      const time = new Date(expires).getTime();
      if (Number.isFinite(time)) return time;
    }

    const maxAge =
      sess?.cookie?.originalMaxAge ?? sess?.cookie?.maxAge;

    if (Number.isSafeInteger(maxAge) && maxAge > 0) {
      return Date.now() + maxAge;
    }

    return Date.now() + this.defaultTtlMs;
  }

  get(sid, callback) {
    (async () => {
      await this.ready;

      const result = await this.client.execute({
        sql: 'SELECT session_json, expires_at_ms FROM nt_web_sessions WHERE sid = ?',
        args: [sid]
      });

      const row = result.rows[0];

      if (!row || Number(row.expires_at_ms) <= Date.now()) {
        if (row) {
          await this.client.execute({
            sql: 'DELETE FROM nt_web_sessions WHERE sid = ?',
            args: [sid]
          });
        }
        return null;
      }

      return JSON.parse(row.session_json);
    })().then(sess => callback(null, sess), callback);
  }

  set(sid, sess, callback = () => {}) {
    (async () => {
      await this.ready;

      await this.client.execute({
        sql: `INSERT INTO nt_web_sessions
              (sid, session_json, expires_at_ms)
              VALUES (?, ?, ?)
              ON CONFLICT(sid) DO UPDATE SET
                session_json = excluded.session_json,
                expires_at_ms = excluded.expires_at_ms`,
        args: [
          sid,
          JSON.stringify(sess),
          this.expiresAt(sess)
        ]
      });
    })().then(() => callback(null), callback);
  }

  destroy(sid, callback = () => {}) {
    (async () => {
      await this.ready;

      await this.client.execute({
        sql: 'DELETE FROM nt_web_sessions WHERE sid = ?',
        args: [sid]
      });
    })().then(() => callback(null), callback);
  }

  touch(sid, sess, callback = () => {}) {
    (async () => {
      await this.ready;

      await this.client.execute({
        sql: 'UPDATE nt_web_sessions SET expires_at_ms = ? WHERE sid = ?',
        args: [this.expiresAt(sess), sid]
      });
    })().then(() => callback(null), callback);
  }
}

module.exports = TursoSessionStore;
'use strict';

const turso = require('./turso-client');

function createDatabaseClient(client) {
  function queries(connection) {
    return {
      async get(sql, ...args) {
        const result = await connection.execute({ sql, args });
        return result.rows[0] ?? null;
      },

      async all(sql, ...args) {
        const result = await connection.execute({ sql, args });
        return result.rows;
      },

      async run(sql, ...args) {
        const result = await connection.execute({ sql, args });

        return {
          changes: result.rowsAffected,
          lastInsertRowid: result.lastInsertRowid
        };
      }
    };
  }

  const db = queries(client);

  db.exec = async function (sql) {
    await client.executeMultiple(sql);
  };

  db.transaction = async function (work) {
    const tx = await client.transaction('write');

    try {
      const result = await work(queries(tx));
      await tx.commit();
      return result;
    } catch (error) {
      if (!tx.closed) {
        try {
          await tx.rollback();
        } catch (rollbackError) {
          if (error instanceof Error) error.rollbackError = rollbackError;
        }
      }
      throw error;
    } finally {
      tx.close();
    }
  };

  db.close = async () => {
    if (typeof client.close === 'function') await client.close();
  };

  return db;
}

module.exports = createDatabaseClient(turso);
module.exports.createDatabaseClient = createDatabaseClient;
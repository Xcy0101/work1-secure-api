'use strict';

const { createDb } = require('./db');
const { createApp } = require('./app');

const PORT = Number(process.env.PORT) || 3000;
const DB_FILE = process.env.DB_FILE || 'app.db';

const db = createDb(DB_FILE);
const app = createApp(db);

app.listen(PORT, () => {
  console.log('work1-secure-api listening on http://127.0.0.1:' + PORT);
});
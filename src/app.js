const express = require('express');
const routes = require('./routes');

const app = express();

app.disable('x-powered-by');
app.use(express.json());

app.use('/', routes);

app.use((req, res) => {
    res.status(404).json({ status: 'error', message: 'Not found' });
});

module.exports = app;
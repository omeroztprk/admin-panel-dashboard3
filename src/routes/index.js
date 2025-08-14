const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    res.json({
        name: 'Admin Panel API',
        message: 'API is running',
        version: '1.0.0'
    });
});

router.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString()
    });
});

module.exports = router;
const express = require('express')
const controller = require('../controllers/search/search.controller')
const router = express.Router();

router.get('/items', controller.getItem);

module.exports = router;

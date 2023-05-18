const express = require('express')
const controller = require('../controllers/statistic/statistic.controller')
const router = express.Router();

router.get('/getOrderToday',controller.getOrderToday),
router.get('/getProductId',controller.getProductId)

module.exports = router;

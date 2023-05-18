const express = require('express')
const { authJWT } = require('../middlewares')
const controller = require('../controllers/notification/notification.controller')
const router = express.Router()

/**
 * @swagger
 * /api/order/getAllNotifications:
 *  get:
 *      summary: Get All Notifications
 *      description: Get list contains all notifications
 *      responses:
 *          200:
 *              description: Get list successfully
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              data:
 *                                  type: array
 *                                  items: 
 *                                      type: object
 *                                      properties:
 *                                          id: 
 *                                              type: string
 *                                              description: Notification ID
 *                                              example: 1234566789abc
 *                                          orderId: 
 *                                              type: string
 *                                              description: Order ID
 *                                              example: 1234566789abc
 *                                          for: 
 *                                              type: string
 *                                              description: For Role Of User
 *                                              example: admin
 *                                          type: 
 *                                              type: string
 *                                              description: Typ Of Notification
 *                                              example: order
 *                                          customer: 
 *                                              type: object
 *                                              properties: 
 *                                                  id: 
 *                                                      type: string
 *                                                      description: Customer ID
 *                                                      example: 123abc
 *                                                  name: 
 *                                                      type: string
 *                                                      description: Customer Name
 *                                                      example: XYZ
 *                                          seen: 
 *                                              type: boolean
 *                                              description: Is Seen
 *                                              example: false
 *          401:
 *              description: Unauthorized.
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  type: string
 *                                  example: Unauthorized.
 *          402:
 *              description: No Token Provided.
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  type: string
 *                                  example: No Token Provided.
 *          403:
 *              description: Required Admin Role.
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  type: string
 *                                  example: Required Admin Role.
 *          500:
 *              description: Internal Server Error.
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  type: string
 *                                  example: Internal Server Error.
 */
router.get(
    '/getAllNotifications',
    [
        authJWT.verifyToken,
        authJWT.isAdmin
    ],
    controller.getAllNotifications
)

module.exports = router
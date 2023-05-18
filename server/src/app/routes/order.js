const express = require('express')
const { celebrate } = require('celebrate')
const { authJWT } = require('../middlewares')
const controller = require('../controllers/order/order.controller')
const { getOrderDto, declineOrderDto, confirmOrderDto } = require('../models/dto/order.dto')
const router = express.Router()

/**
 * @swagger
 * /api/order/getAllOrders:
 *  get:
 *      summary: Get All Orders
 *      description: Get list contains all orders
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
 *                                              description: Order ID
 *                                              example: 1234566789abc
 *                                          customerId: 
 *                                              type: string
 *                                              description: Customer ID
 *                                              example: 1234566789abc
 *                                          status: 
 *                                              type: string
 *                                              description: Order Status
 *                                              example: pending
 *                                          confirmByAdminId: 
 *                                              type: string
 *                                              description: Admin Id confirmed Order
 *                                              example: 123456789abc
 *                                          createdAt: 
 *                                              type: string
 *                                              format: date
 *                                              description: Created Order Time
 *                                              example: 11:11:11 Thur 11/11/2022
 *                                          updatedAt: 
 *                                              type: string
 *                                              format: date
 *                                              description: Created Order Time
 *                                              example: 11:11:11 Thur 11/11/2022
 *                                          totalAmount: 
 *                                              type: number
 *                                              description: Order Amount
 *                                              example: 123123.123
 *                                          products: 
 *                                              type: array
 *                                              items:
 *                                                  type: object
 *                                                  properties:
 *                                                      id:
 *                                                          type: string
 *                                                          description: Product ID 
 *                                                          example: 123123123abc
 *                                                      quantity:
 *                                                          type: number
 *                                                          description: Quantity Of Product In Order
 *                                                          example: 2
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
    '/getAllOrders',
    [
        authJWT.verifyToken,
        authJWT.isAdmin
    ],
    controller.getAllOrders
)

/**
 * @swagger
 * /api/order/getOrder:
 *  post:
 *      summary: Get Order
 *      description: Get order by id
 *      requestBody:
 *          required: true
 *          content:
 *              application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          id: 
 *                              type: string
 *                              example: orderId
 *      responses:
 *          200:
 *              description: Get order successfully
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              data:
 *                                      type: object
 *                                      properties:
 *                                          id: 
 *                                              type: string
 *                                              description: Order ID
 *                                              example: 1234566789abc
 *                                          customerId: 
 *                                              type: string
 *                                              description: Customer ID
 *                                              example: 1234566789abc
 *                                          status: 
 *                                              type: string
 *                                              description: Order Status
 *                                              example: pending
 *                                          confirmByAdminId: 
 *                                              type: string
 *                                              description: Admin Id confirmed Order
 *                                              example: 123456789abc
 *                                          createdAt: 
 *                                              type: string
 *                                              format: date
 *                                              description: Created Order Time
 *                                              example: 11:11:11 Thur 11/11/2022
 *                                          updatedAt: 
 *                                              type: string
 *                                              format: date
 *                                              description: Created Order Time
 *                                              example: 11:11:11 Thur 11/11/2022
 *                                          totalAmount: 
 *                                              type: number
 *                                              description: Order Amount
 *                                              example: 123123.123
 *                                          products: 
 *                                              type: array
 *                                              items:
 *                                                  type: object
 *                                                  properties:
 *                                                      id:
 *                                                          type: string
 *                                                          description: Product ID 
 *                                                          example: 123123123abc
 *                                                      quantity:
 *                                                          type: number
 *                                                          description: Quantity Of Product In Order
 *                                                          example: 2
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
router.post(
    '/getOrder',
    [
        celebrate(getOrderDto),
        authJWT.verifyToken,
        authJWT.isAdmin
    ],
    controller.getOrder
)

/**
 * @swagger
 * /api/order/confirmOrder:
 *  post:
 *      summary: Confirm Order
 *      description: Confirm order by id
 *      requestBody:
 *          required: true
 *          content:
 *              application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          id: 
 *                              type: string
 *                              example: orderId
 *      responses:
 *          200:
 *              description: Confirm order successfully
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  type: string
 *                                  example: Confirm Order Successfully.
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
router.post(
    '/confirmOrder',
    [
        celebrate(confirmOrderDto),
        authJWT.verifyToken,
        authJWT.isAdmin
    ],
    controller.confirmOrder
)

/**
 * @swagger
 * /api/order/declineOrder:
 *  post:
 *      summary: Decline Order
 *      description: Decline order by id
 *      requestBody:
 *          required: true
 *          content:
 *              application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          id: 
 *                              type: string
 *                              example: orderId
 *                          reason: 
 *                              type: string
 *                              example: Sold Out!
 *      responses:
 *          200:
 *              description: Decline order successfully
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  type: string
 *                                  example: Decline Order Successfully.
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
router.post(
    '/declineOrder',
    [
        celebrate(declineOrderDto),
        authJWT.verifyToken,
        authJWT.isAdmin
    ],
    controller.declineOrder
)
router.post(
    '/createOrder',
    [
        authJWT.verifyToken,
    ],
    controller.createOrder)

module.exports = router
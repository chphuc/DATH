const express = require('express')
const { celebrate } = require('celebrate')
const { verifySignUp } = require('../middlewares')
const controller = require('../controllers/auth/auth.controller')
const { signUpUserDto, signInUserDto } = require('../models/dto/auth.dto')
const router = express.Router()

/**
 * @swagger
 * /api/auth/signup:
 *  post:
 *      summary: Sign Up
 *      description: Register new accout
 *      requestBody:
 *          required: true
 *          content:
 *              application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          username: 
 *                              type: string
 *                              example: username
 *                          email: 
 *                              type: email
 *                              example: user@mail.com
 *                          password: 
 *                              type: string
 *                              example: password123
 *                          repeat_password: 
 *                              type: string
 *                              example: password123
 *      responses:
 *          200:
 *              description: Register successfully.
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  type: string
 *                                  example: Register successfully.
 *          400:
 *              description: User already existed.
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  type: string
 *                                  example: User already existed.
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
    '/signup',
    [
        celebrate(signUpUserDto),
        verifySignUp.checkDuplicateUsernameOrEmail,
        verifySignUp.checkRoleExisted
    ],
    controller.signup
)

/**
 * @swagger
 * /api/auth/signin:
 *  post:
 *      summary: Login
 *      description: Login to app
 *      requestBody:
 *          required: true
 *          content:
 *              application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          username: 
 *                              type: string
 *                              example: username
 *                          password: 
 *                              type: string
 *                              example: password123
 *      responses:
 *          200:
 *              description: Login successfully.
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              accessToken:
 *                                  type: string
 *                                  example: accesstoken
 *                              expiresIn:
 *                                  type: number
 *                                  example: 3600
 *          401:
 *              description: Invalid password.
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  type: string
 *                                  example: Invalid password.
 *          404:
 *              description: User not found.
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  type: string
 *                                  example: User not found.
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
    '/signin',
    [
        celebrate(signInUserDto),
    ],
    controller.signin
)

module.exports = router
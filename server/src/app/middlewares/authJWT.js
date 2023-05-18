const jwt = require('jsonwebtoken')
const db = require('../data')
const User = db.user
const Role = db.role

const verifyToken = (req, res, next) => {
    let accessToken = req.cookies?.act

    if (!accessToken) {
        return res.status(401).send({ message: 'Unauthorized!' })
    }

    jwt.verify(accessToken, process.env.ACCESS_SECRET_KEY, (err, decoded) => {
        if (err || !decoded?.id) {
            let refreshToken = req.cookies?.rft
            if (!refreshToken) {
                return res.status(401).send({ message: 'Unauthorized!', error: err })
            }

            jwt.verify(refreshToken, process.env.REFRESH_SECRET_KEY, (err, decoded) => {
                if (err || !decoded?.id) {
                    return res.status(401).send({ message: 'Unauthorized!', error: err })
                }

                var accessToken = jwt.sign({ id: decoded.id }, process.env.ACCESS_SECRET_KEY, {
                    expiresIn: `${process.env.ACCESS_TOKEN_EXPIRESIN}m`
                })

                res.cookie('act', accessToken, {
                    httpOnly: true,
                    sameSite: 'strict',
                    secure: true,
                    path: '/',
                    maxAge: process.env.ACCESS_TOKEN_EXPIRESIN*1000
                })
                req.userId = decoded.id
                next()
            })
            return
        }
        req.userId = decoded.id
        next()
    })
}

const isAdmin = (req, res, next) => {
    User.findById(req.userId).exec((err, user) => {
        if (err) {
            res.status(500).send({ message: err })
            return;
        }

        Role.findOne({
            _id: user.role
        }, (err, role) => {
            if (err) {
                res.status(500).send({ message: err })
                return;
            }

            if (role?.name === 'admin') {
                next()
                return
            }

            res.status(403).send({ message: 'Require Admin role!' })
            return;
        })
    })
}

const isModerator = (req, res, next) => {
    User.findById(req.userId).exec((err, user) => {
        if (err) {
            res.status(500).send({ message: err })
            return;
        }

        Role.findOne({
            _id: user.role
        }, (err, role) => {
            if (err) {
                res.status(500).send({ message: err })
                return;
            }
            
            if (role.name === 'moderator') {
                next()
                return
            }

            res.status(403).send({ message: 'Require Moderator role!' })
            return;
        })
    })
}

const authJWT = {
    verifyToken,
    isAdmin,
    // isModerator
}
module.exports = authJWT
const db = require('../data')
const ROLES = db.ROLES
const User = db.user

const checkDuplicateUsernameOrEmail = (req, res, next) => {
    User.findOne({
        username: req.body.username,
    }).exec((err, user) => {
        if (err) {
            res.status(500).send({ message: `checkDuplicateUsernameOrEmail: username ${err}` })
            return;
        }

        if (user) {
            res.status(400).send({ message: 'Failed! Username already in use!' })
            return;
        }

        User.findOne({
            email: req.body.email,
        }).exec((err, user) => {
            if (err) {
                res.status(500).send({ message: `checkDuplicateUsernameOrEmail: email ${err}` })
                return;
            }

            if (user) {
                res.status(400).send({ message: 'Failed! Email already in use!' })
                return;
            }

            next()
        })
    })
}

const checkRoleExisted = (req, res, next) => {
    if (req.body.role) {
        if (!ROLES.includes(req.body.role)) {
            res.status(400).send({ message: `Failed! Role ${req.body.role} doesn't exist!` })
            return false
        }
        next()
    }
}

const verifySignUp = {
    checkDuplicateUsernameOrEmail,
    checkRoleExisted
}

module.exports = verifySignUp
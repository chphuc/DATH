const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const db = require('../../data')
const User = db.user
const Role = db.role

class AuthController {

    // [POST] api/auth/signup
    signup = (req, res) => {
        const user = new User({
            username: req.body.username,
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password, 8)
        })

        console.log('api signup');
    
        user.save((err, user) => {
            if (err) {
                res.status(500).send({ message: err })
                return
            }
    
            Role.findOne(
                { name: req.body.role }
                , (err, role) => {
                    if (err) {
                        res.status(500).send({ message: err })
                        return
                    }

                    user.role = role._id
                    user.save((err, user) => {
                        if (err) {
                            res.status(500).send({ message: err })
                            return
                        }
                        res.send({ message: 'User was registered successfully!' })
                    })
                }
            )
        })
    }

    // [POST] api/auth/signin
    signin(req, res) {
        User.findOne({
            username: req.body.username
        })
        .populate("role", "-__v")
        .exec((err, user) => {
            if (err) {
                res.status(500).send({ message: err })
                return
            }
    
            if (!user) {
                return res.status(404).send({ message: "User Not found." });
            }
    
            var passwordIsValid = bcrypt.compareSync(
                req.body.password,
                user.password
            );
    
            if (!passwordIsValid) {
                return res.status(401).send({
                    accessToken: null,
                    message: 'Invalid password!'
                })
            }
            
            var accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_SECRET_KEY, {
                expiresIn: `${process.env.ACCESS_TOKEN_EXPIRESIN}m`
            })
            
            var refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_SECRET_KEY, {
                expiresIn: `${process.env.REFRESH_TOKEN_EXPIRESIN}m`
            })
            
            res
            .status(200)
            .cookie('act', accessToken, {
                httpOnly: true,
                sameSite: 'strict',
                secure: true,
                path: '/',
                maxAge: process.env.ACCESS_TOKEN_EXPIRESIN*1000*60
            })
            .cookie('rft', refreshToken, {
                httpOnly: true,
                sameSite: 'strict',
                secure: true,
                path: '/',
                maxAge: process.env.REFRESH_TOKEN_EXPIRESIN*1000*60
            })

            if (req.body.role === 'admin') {
                Role.findOne({
                    _id: user.role
                }, (err, role) => {
                    if (err) {
                        res.status(500).send({ message: err })
                        return;
                    }
        
                    if (role?.name !== 'admin') {
                        return res.status(403).send({ message: 'Require Admin role!' })
                    }

                    return res.send({
                        accessToken: accessToken,
                        expiresIn: process.env.ACCESS_TOKEN_EXPIRESIN + 'm'
                    })
                })
            }
            else if (req.body.role !== 'user') {
                return res.status(403).send({ message: 'Invalid role!' })
            }
            else {
                return res.send({
                    accessToken: accessToken,
                    expiresIn: process.env.ACCESS_TOKEN_EXPIRESIN + 'm'
                })
            }
        })
    }
}

module.exports = new AuthController
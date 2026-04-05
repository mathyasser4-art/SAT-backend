const userModel = require('../../DB/models/user.model')
const jwt = require('jsonwebtoken');
const getJwtSecret = require('../services/jwtSecret');

const isDashboardAuthDisabled = () => process.env.DISABLE_ADMIN_AUTH === 'true';

// Get authorization token from either 'authorization' or 'authrization' header (backwards compatibility)
const getAuthToken = (headers) => {
    return headers.authorization || headers.authrization;
};

const allowDashboardBypass = (req, next, role = 'admin') => {
    if (isDashboardAuthDisabled()) {
        req.userData = { role };
        next();
        return true;
    }

    return false;
};

const userAuth = async (req, res, next) => {
    try {
        const authorization = getAuthToken(req.headers);
        if (authorization) {
            if (authorization.startsWith(process.env.AUTH_SECRET_KEY)) {
                const userToken = authorization.split(process.env.AUTH_SECRET_KEY)[1]
                const { id } = jwt.verify(userToken, getJwtSecret())
                const userFounded = await userModel.findById(id)
                if (userFounded) {
                    if (userFounded.verify) {
                        if (!userFounded.block) {
                            if (userFounded.role == 'User') {
                                req.userData = userFounded
                                next()
                            } else {
                                res.json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.json({ message: 'this account is not verify' })
                    }
                } else {
                    res.json({ message: 'this user is not found' })
                }
            } else {
                res.json({ message: 'auth secret key is wrong' })
            }
        } else {
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const adminAuth = async (req, res, next) => {
    if (allowDashboardBypass(req, next, 'admin')) {
        return;
    }
    try {
        const authorization = getAuthToken(req.headers);
        if (authorization) {
            if (authorization.startsWith(process.env.AUTH_SECRET_KEY)) {
                const userToken = authorization.split(process.env.AUTH_SECRET_KEY)[1]
                const { id } = jwt.verify(userToken, getJwtSecret())
                const userFounded = await userModel.findById(id)
                if (userFounded) {
                    if (userFounded.verify) {
                        if (!userFounded.block) {
                            if (userFounded.role == 'admin') {
                                req.userData = userFounded
                                next()
                            } else {
                                res.json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.json({ message: 'this account is not verify' })
                    }
                } else {
                    res.json({ message: 'this user is not found' })
                }
            } else {
                res.json({ message: 'auth secret key is wrong' })
            }
        } else {
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const teacherAuth = async (req, res, next) => {
    if (allowDashboardBypass(req, next, 'Teacher')) {
        return;
    }
    try {
        const authorization = getAuthToken(req.headers);
        if (authorization) {
            if (authorization.startsWith(process.env.AUTH_SECRET_KEY)) {
                const userToken = authorization.split(process.env.AUTH_SECRET_KEY)[1]
                const { id } = jwt.verify(userToken, getJwtSecret())
                const userFounded = await userModel.findById(id)
                if (userFounded) {
                    if (userFounded.verify) {
                        if (!userFounded.block) {
                            if (userFounded.role == 'Teacher' && userFounded.disable == false) {
                                req.userData = userFounded
                                next()
                            } else {
                                res.json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.json({ message: 'this account is not verify' })
                    }
                } else {
                    res.json({ message: 'this user is not found' })
                }
            } else {
                res.json({ message: 'auth secret key is wrong' })
            }
        } else {
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const studentAuth = async (req, res, next) => {
    try {
        const authorization = getAuthToken(req.headers);
        if (authorization) {
            if (authorization.startsWith(process.env.AUTH_SECRET_KEY)) {
                const userToken = authorization.split(process.env.AUTH_SECRET_KEY)[1]
                const { id } = jwt.verify(userToken, getJwtSecret())
                const userFounded = await userModel.findById(id)
                if (userFounded) {
                    if (userFounded.verify) {
                        if (!userFounded.block) {
                            if (userFounded.role == 'Student' && userFounded.disable == false) {
                                req.userData = userFounded
                                next()
                            } else {
                                res.json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.json({ message: 'this account is not verify' })
                    }
                } else {
                    res.json({ message: 'this user is not found' })
                }
            } else {
                res.json({ message: 'auth secret key is wrong' })
            }
        } else {
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const schoolAuth = async (req, res, next) => {
    if (allowDashboardBypass(req, next, 'School')) {
        return;
    }
    try {
        const authorization = getAuthToken(req.headers);
        if (authorization) {
            if (authorization.startsWith(process.env.AUTH_SECRET_KEY)) {
                const userToken = authorization.split(process.env.AUTH_SECRET_KEY)[1]
                const { id } = jwt.verify(userToken, getJwtSecret())
                const userFounded = await userModel.findById(id)
                if (userFounded) {
                    if (userFounded.verify) {
                        if (!userFounded.block) {
                            if (userFounded.role == 'School' && userFounded.disable == false) {
                                req.userData = userFounded
                                next()
                            } else {
                                res.json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.json({ message: 'this account is not verify' })
                    }
                } else {
                    res.json({ message: 'this user is not found' })
                }
            } else {
                res.json({ message: 'auth secret key is wrong' })
            }
        } else {
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const itAuth = async (req, res, next) => {
    if (allowDashboardBypass(req, next, 'IT')) {
        return;
    }
    try {
        const authorization = getAuthToken(req.headers);
        if (authorization) {
            if (authorization.startsWith(process.env.AUTH_SECRET_KEY)) {
                const userToken = authorization.split(process.env.AUTH_SECRET_KEY)[1]
                const { id } = jwt.verify(userToken, getJwtSecret())
                const userFounded = await userModel.findById(id)
                if (userFounded) {
                    if (userFounded.verify) {
                        if (!userFounded.block) {
                            if (userFounded.role == 'School' || userFounded.role == 'IT') {
                                if (userFounded.disable == false) {
                                    req.userData = userFounded
                                    next()
                                } else {
                                    res.json({ message: 'You do not have access to complete this operation' })
                                }
                            } else {
                                res.json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.json({ message: 'this account is not verify' })
                    }
                } else {
                    res.json({ message: 'this user is not found' })
                }
            } else {
                res.json({ message: 'auth secret key is wrong' })
            }
        } else {
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const supervisorAuth = async (req, res, next) => {
    if (allowDashboardBypass(req, next, 'Supervisor')) {
        return;
    }
    try {
        const authorization = getAuthToken(req.headers);
        if (authorization) {
            if (authorization.startsWith(process.env.AUTH_SECRET_KEY)) {
                const userToken = authorization.split(process.env.AUTH_SECRET_KEY)[1]
                const { id } = jwt.verify(userToken, getJwtSecret())
                const userFounded = await userModel.findById(id)
                if (userFounded) {
                    if (userFounded.verify) {
                        if (!userFounded.block) {
                            if (userFounded.role == 'Supervisor' && userFounded.disable == false) {
                                req.userData = userFounded
                                next()
                            } else {
                                res.json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.json({ message: 'this account is not verify' })
                    }
                } else {
                    res.json({ message: 'this user is not found' })
                }
            } else {
                res.json({ message: 'auth secret key is wrong' })
            }
        } else {
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

module.exports = { userAuth, adminAuth, teacherAuth, studentAuth, schoolAuth, itAuth, supervisorAuth }

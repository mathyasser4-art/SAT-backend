const userModel = require('../../DB/models/user.model')
const jwt = require('jsonwebtoken');

const extractTokenFromHeader = (headers) => {
    return headers.authorization || headers.authrization || headers['auth-token'];
};

const getTokenFromAuthHeader = (authHeader) => {
    if (!authHeader) return null;
    if (process.env.AUTH_SECRET_KEY && authHeader.startsWith(process.env.AUTH_SECRET_KEY)) {
        return authHeader.slice(process.env.AUTH_SECRET_KEY.length);
    }
    if (authHeader.startsWith('Bearer ')) {
        return authHeader.slice(7);
    }
    if (authHeader.startsWith('Token ')) {
        return authHeader.slice(6);
    }
    return authHeader;
};

const userAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
                const { id } = jwt.verify(authHeader, process.env.TOKEN_SECRET_KEY)
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
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const adminAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
                const { id } = jwt.verify(authHeader, process.env.TOKEN_SECRET_KEY)
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
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const teacherAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
                const { id } = jwt.verify(authHeader, process.env.TOKEN_SECRET_KEY)
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
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const studentAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
                const { id } = jwt.verify(authHeader, process.env.TOKEN_SECRET_KEY)
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
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const schoolAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
                const { id } = jwt.verify(authHeader, process.env.TOKEN_SECRET_KEY)
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
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const itAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
                const { id } = jwt.verify(authHeader, process.env.TOKEN_SECRET_KEY)
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
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const supervisorAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
                const { id } = jwt.verify(authHeader, process.env.TOKEN_SECRET_KEY)
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
            res.json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const publicAdminAuth = (req, res, next) => {
  req.userData = { role: 'public-admin' }; // Bypass auth
  next();
};

module.exports = { userAuth, adminAuth, teacherAuth, studentAuth, schoolAuth, itAuth, supervisorAuth, publicAdminAuth }


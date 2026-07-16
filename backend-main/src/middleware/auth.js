const userModel = require('../../DB/models/user.model')
const jwt = require('jsonwebtoken');

const extractTokenFromHeader = (headers) => {
    return headers.authorization || headers.authrization || headers['auth-token'];
};

const getTokenFromAuthHeader = (authHeader) => {
    if (!authHeader) return null;
    let token = authHeader;
    if (process.env.AUTH_SECRET_KEY && token.startsWith(process.env.AUTH_SECRET_KEY)) {
        token = token.slice(process.env.AUTH_SECRET_KEY.length);
    } else if (token.startsWith('pracYas09')) {
        token = token.slice('pracYas09'.length);
    }
    if (token.startsWith('Bearer ')) {
        token = token.slice(7);
    }
    if (token.startsWith('Token ')) {
        token = token.slice(6);
    }
    return token;
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
                            if (['User', 'Teacher', 'Student', 'Admin', 'School', 'IT', 'Supervisor'].includes(userFounded.role)) {
                                req.userData = userFounded
                                next()
                            } else {
                                res.status(403).json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.status(403).json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.status(401).json({ message: 'this account is not verify' })
                    }
                } else {
                    res.status(404).json({ message: 'this user is not found' })
                }
        } else {
            res.status(401).json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(500).json({ message: error.message })
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
                                res.status(403).json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.status(403).json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.status(401).json({ message: 'this account is not verify' })
                    }
                } else {
                    res.status(404).json({ message: 'this user is not found' })
                }
        } else {
            res.status(401).json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(500).json({ message: error.message })
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
                                res.status(403).json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.status(403).json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.status(401).json({ message: 'this account is not verify' })
                    }
                } else {
                    res.status(404).json({ message: 'this user is not found' })
                }
        } else {
            res.status(401).json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(500).json({ message: error.message })
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
                                res.status(403).json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.status(403).json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.status(401).json({ message: 'this account is not verify' })
                    }
                } else {
                    res.status(404).json({ message: 'this user is not found' })
                }
        } else {
            res.status(401).json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(500).json({ message: error.message })
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
                                res.status(403).json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.status(403).json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.status(401).json({ message: 'this account is not verify' })
                    }
                } else {
                    res.status(404).json({ message: 'this user is not found' })
                }
        } else {
            res.status(401).json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(500).json({ message: error.message })
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
                                    res.status(403).json({ message: 'You do not have access to complete this operation' })
                                }
                            } else {
                                res.status(403).json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.status(403).json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.status(401).json({ message: 'this account is not verify' })
                    }
                } else {
                    res.status(404).json({ message: 'this user is not found' })
                }
        } else {
            res.status(401).json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(500).json({ message: error.message })
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
                                res.status(403).json({ message: 'You do not have access to complete this operation' })
                            }
                        } else {
                            res.status(403).json({ message: 'You cannot perform this transaction. This account has been blocked' })
                        }
                    } else {
                        res.status(401).json({ message: 'this account is not verify' })
                    }
                } else {
                    res.status(404).json({ message: 'this user is not found' })
                }
        } else {
            res.status(401).json({ message: 'this user access token is not found' })
        }
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
}

const publicAdminAuth = (req, res, next) => {
  req.userData = { role: 'public-admin' }; // Bypass auth
  next();
};

module.exports = { userAuth, adminAuth, teacherAuth, studentAuth, schoolAuth, itAuth, supervisorAuth, publicAdminAuth }

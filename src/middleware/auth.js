const userModel = require('../../DB/models/user.model')
const { verifySessionToken } = require('../services/sessions');

// WARNING: When DISABLE_ADMIN_AUTH=true, requests sent WITHOUT any token pass adminAuth.
// Only adminAuth honours it: the SAT dashboard only calls adminAuth routes (and public ones),
// so teacher/school/IT/supervisor routes always require a real token.
// Set DISABLE_ADMIN_AUTH=false on Railway once the dashboard sends its admin token on every call.
const isDashboardAuthDisabled = () => process.env.DISABLE_ADMIN_AUTH === 'true';

const allowDashboardBypass = (req, next) => {
    if (isDashboardAuthDisabled()) {
        const rawAuthHeader = req.headers['authorization'] || req.headers['auth-token'] || req.headers['authrization'] || req.headers['token'];
        if (!rawAuthHeader) {
            req.userData = { role: 'Admin' };
            next();
            return true;
        }
    }

    return false;
};

// The roles /admin/login lets into the dashboard. It compares them case-insensitively,
// so adminAuth does too (the stored enum values are 'Admin' and 'IT').
const DASHBOARD_ROLES = ['admin', 'it', 'superadmin'];
const isDashboardRole = (role) => typeof role === 'string' && DASHBOARD_ROLES.includes(role.trim().toLowerCase());

// NOTE: 'authrization' (misspelled) is intentional — most frontend API calls send this header.
const extractTokenFromHeader = (headers) => {
    return headers.authorization || headers.authrization || headers['auth-token'];
};

// Clients prefix the JWT with a fixed label (e.g. "pracYas09"). The label is NOT a secret and
// grants nothing by itself: it is stripped here and the remaining JWT is still fully verified.
const TOKEN_PREFIXES = [process.env.AUTH_SECRET_KEY, 'pracYas09'].filter(Boolean);

const getTokenFromAuthHeader = (authHeader) => {
    if (!authHeader) return null;

    for (const prefix of TOKEN_PREFIXES) {
        if (authHeader.startsWith(prefix)) {
            return authHeader.slice(prefix.length);
        }
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
            const { id } = await verifySessionToken(req, authHeader)
            const userFounded = await userModel.findById(id)
            if (userFounded) {
                if (userFounded.verify) {
                    if (!userFounded.block) {
                        if (['User', 'Teacher', 'Student', 'Admin', 'School', 'IT', 'Supervisor', 'Parent'].includes(userFounded.role)) {
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
        res.status(error.status || 500).json({ message: error.message, code: error.code })
    }
}

const adminAuth = async (req, res, next) => {
    if (allowDashboardBypass(req, next)) {
        return;
    }
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
            const { id } = await verifySessionToken(req, authHeader)
            const userFounded = await userModel.findById(id)
            if (userFounded) {
                if (userFounded.verify !== false) {
                    if (!userFounded.block) {
                        if (isDashboardRole(userFounded.role)) {
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
        res.status(error.status || 500).json({ message: error.message, code: error.code })
    }
}

const teacherAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
            const { id } = await verifySessionToken(req, authHeader)
            const userFounded = await userModel.findById(id)
            if (userFounded) {
                if (userFounded.verify !== false) {
                    if (!userFounded.block) {
                        if (['Teacher', 'School', 'Admin', 'IT', 'Supervisor'].includes(userFounded.role) && !userFounded.disable) {
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
        res.status(error.status || 500).json({ message: error.message, code: error.code })
    }
}

const studentAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
            const { id } = await verifySessionToken(req, authHeader)
            const userFounded = await userModel.findById(id)
            if (userFounded) {
                if (userFounded.verify !== false) {
                    if (!userFounded.block) {
                        if (['Student', 'User', 'Teacher', 'School', 'Admin'].includes(userFounded.role) && !userFounded.disable) {
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
        res.status(error.status || 500).json({ message: error.message, code: error.code })
    }
}

const schoolAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
            const { id } = await verifySessionToken(req, authHeader)
            const userFounded = await userModel.findById(id)
            if (userFounded) {
                if (userFounded.verify !== false) {
                    if (!userFounded.block) {
                        if (['School', 'Teacher', 'Admin', 'IT', 'Supervisor'].includes(userFounded.role) && !userFounded.disable) {
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
        res.status(error.status || 500).json({ message: error.message, code: error.code })
    }
}

const itAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
            const { id } = await verifySessionToken(req, authHeader)
            const userFounded = await userModel.findById(id)
            if (userFounded) {
                if (userFounded.verify !== false) {
                    if (!userFounded.block) {
                        if (['School', 'IT', 'Admin', 'Teacher'].includes(userFounded.role) && !userFounded.disable) {
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
        res.status(error.status || 500).json({ message: error.message, code: error.code })
    }
}

const itOrTeacherAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
            const { id } = await verifySessionToken(req, authHeader)
            const userFounded = await userModel.findById(id)
            if (userFounded) {
                if (userFounded.verify !== false) {
                    if (!userFounded.block) {
                        if (['School', 'IT', 'Teacher', 'Admin', 'Supervisor'].includes(userFounded.role) && !userFounded.disable) {
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
        res.status(error.status || 500).json({ message: error.message, code: error.code })
    }
}

const supervisorAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
            const { id } = await verifySessionToken(req, authHeader)
            const userFounded = await userModel.findById(id)
            if (userFounded) {
                if (userFounded.verify !== false) {
                    if (!userFounded.block) {
                        if (['Supervisor', 'School', 'Teacher', 'Admin'].includes(userFounded.role) && !userFounded.disable) {
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
        res.status(error.status || 500).json({ message: error.message, code: error.code })
    }
}

const parentAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = extractTokenFromHeader(req.headers);
        const authHeader = getTokenFromAuthHeader(rawAuthHeader);
        if (authHeader) {
            const { id } = await verifySessionToken(req, authHeader)
            const userFounded = await userModel.findById(id)
            if (userFounded) {
                if (userFounded.verify !== false) {
                    if (!userFounded.block) {
                        if (['Parent', 'Admin', 'School', 'Teacher'].includes(userFounded.role) && !userFounded.disable) {
                            req.userData = userFounded
                            next()
                        } else {
                            res.status(403).json({ message: 'You do not have access to parent portal' })
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
        res.status(error.status || 500).json({ message: error.message, code: error.code })
    }
}

module.exports = { userAuth, adminAuth, teacherAuth, studentAuth, schoolAuth, itAuth, itOrTeacherAuth, supervisorAuth, parentAuth }

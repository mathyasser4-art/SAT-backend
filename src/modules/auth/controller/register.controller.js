const userModel = require('../../../../DB/models/user.model')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const getJwtSecret = require('../../../services/jwtSecret');
const { normalizeEmail, emailQuery } = require('../../../services/accountGuard');

const register = async (req, res) => {
    try {
        let { email, password, cPassword, phone, userName } = req.body;
        const cleanPhone = phone ? phone.toString().trim() : '';
        const rawPhoneDigits = cleanPhone.replace(/\D/g, '');
        if (!email && rawPhoneDigits) {
            email = `${rawPhoneDigits}@satarea.user`;
            req.body.email = email;
        }

        if (email) {
            email = normalizeEmail(email);
            req.body.email = email;
        }

        const queryOr = [];
        if (email) queryOr.push({ email: emailQuery(email) });
        if (cleanPhone) queryOr.push({ phone: cleanPhone });
        if (rawPhoneDigits && rawPhoneDigits !== cleanPhone) queryOr.push({ phone: rawPhoneDigits });

        const findUser = await userModel.findOne({ $or: queryOr.length > 0 ? queryOr : [{ email }] });
        if (!findUser) {
            if (password == cPassword) {
                const saltRounds = parseInt(process.env.SALTROUNDS) || 10;
                const hashPassword = await bcrypt.hash(password, saltRounds);
                req.body.password = hashPassword;
                req.body.verify = true; // Auto-verify new users - no email verification needed
                if (!req.body.role) req.body.role = 'User';
                if (cleanPhone) req.body.phone = cleanPhone;
                if (!req.body.trialStartDate) req.body.trialStartDate = new Date();
                if (!req.body.trialExpiresAt) req.body.trialExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
                if (typeof req.body.isSubscribed === 'undefined') req.body.isSubscribed = false;

                const addUser = new userModel(req.body);
                const userData = await addUser.save();
                if (userData) {
                    // Generate token for immediate login
                    const userToken = jwt.sign({ id: userData._id }, getJwtSecret());
                    res.status(201).json({ 
                        message: 'success',
                        userToken,
                        userName: userData.userName,
                        role: userData.role,
                        phone: userData.phone,
                        id: userData._id,
                        trialStartDate: userData.trialStartDate,
                        trialExpiresAt: userData.trialExpiresAt,
                        isSubscribed: userData.isSubscribed || false
                    });
                } else {
                    res.json({ message: 'Error...This account has not been registered to our servers. Please try again' });
                }
            } else {
                res.json({ message: 'The password does not match confirm password' });
            }
        } else {
            res.json({ message: 'This phone number or email is already registered. Please sign in.' });
        }
    } catch (error) {
        res.status(502).json({ message: error.message });
    }
};

module.exports = register
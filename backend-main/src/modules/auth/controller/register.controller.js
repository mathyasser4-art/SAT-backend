const userModel = require('../../../../DB/models/user.model')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const getJwtSecret = require('../../../services/jwtSecret');

const register = async (req, res) => {
    try {
        let { email, password, cPassword, phone, userName } = req.body;
        const cleanPhone = phone ? phone.toString().trim() : '';
        const rawPhoneDigits = cleanPhone.replace(/\D/g, '');
        if (!email && rawPhoneDigits) {
            email = `${rawPhoneDigits}@satarea.user`;
            req.body.email = email;
        }

        const queryOr = [];
        if (email) queryOr.push({ email });
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
                if (!req.body.schoolName) req.body.schoolName = 'General';

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
                        id: userData._id
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
const userModel = require('../../../../DB/models/user.model');
const sendEmail = require('../../../services/sendEmail');
const generateCode = require('../../../services/generateVerificationCode');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const getJwtSecret = require('../../../services/jwtSecret');

const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const findUser = await userModel.findOne({ $or: [{ 'email': email }, { 'userName': email }] }).populate('createdBy', 'userName');

        if (findUser) {
            if (!findUser.verify) {
                findUser.verificationCode = generateCode();
                await findUser.save();
                const emailMessage = `<div style="direction: rtl; padding: 10px 30px;">
                    <p style="font-size: 20px; font-weight: bold; color: #000;">Welcome, ${findUser.fullName || findUser.userName}. We are happy that you have registered with us. Your account verification code is</p>
                    <p style="font-size: 40px; font-weight: bold; color: #000;">${findUser.verificationCode}</p>
                    </div>`;
                sendEmail(email, emailMessage, 'Account verification', 'Practice Papers');
                res.json({ message: 'this account is not verify check your email to get your code verification', isVerify: false });
            } else {
                let checkPassword = await bcrypt.compare(password, findUser.password);

                if (!checkPassword && findUser.password === password) {
                    const saltRounds = parseInt(process.env.SALTROUNDS) || 10;
                    const hashedPassword = await bcrypt.hash(password, saltRounds);
                    await userModel.updateOne({ _id: findUser._id }, { $set: { password: hashedPassword } });
                    checkPassword = true;
                }

                if (checkPassword) {
                    const userToken = jwt.sign({ id: findUser._id }, getJwtSecret());
                    const schoolName = findUser.role === 'School' 
                        ? findUser.userName 
                        : (findUser.createdBy?.userName || 'SAT School');

                    res.json({ 
                        message: 'success', 
                        userToken, 
                        userName: findUser.userName, 
                        role: findUser.role,
                        id: findUser._id,
                        email: findUser.email,
                        schoolName: schoolName
                    });
                } else {
                    res.json({ message: 'wrong password' });
                }
            }
        } else {
            res.json({ message: 'this email or username is not registered' });
        }
    } catch (error) {
        console.error('login error:', error);
        res.status(502).json({ message: error.message });
    }
};

module.exports = login;
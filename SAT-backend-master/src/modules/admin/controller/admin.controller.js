const userModel = require('../../../../DB/models/user.model')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const login = async (req, res) => {
    try {
        const { email, password } = req.body
        // .trim() handles accidental spaces in the email input
        const findUser = await userModel.findOne({ email: email.trim() })
        
        if (findUser) {
            // Convert role to lowercase to make it easy to compare
            const userRole = findUser.role ? findUser.role.trim().toLowerCase() : "";

            // FIX: Allow BOTH the Website Owner ('it') AND the School Owners ('admin')
            if (userRole === 'admin' || userRole === 'it' || userRole === 'superadmin') {
                const checkPassword = bcrypt.compareSync(password, findUser.password)
                
                if (checkPassword) {
                    const userToken = jwt.sign({ id: findUser._id }, process.env.TOKEN_SECRET_KEY);
                    res.json({ message: 'success', userToken })
                } else {
                    res.json({ message: 'wrong password' })
                }
            } else {
                // This message appears if your role in the DB isn't 'it' or 'admin'
                res.json({ message: 'You do not have access to complete this operation' })
            }
        } else {
            res.json({ message: 'this email is not registered' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

module.exports = login
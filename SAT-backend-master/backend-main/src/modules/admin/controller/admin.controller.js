const userModel = require('../../../../DB/models/user.model')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const login = async (req, res) => {
    try {
        const { email, password } = req.body
        // .trim() removes any accidental spaces from the input
        const findUser = await userModel.findOne({ email: email.trim() })
        
        if (findUser) {
            // This line helps us debug by printing the role in your Railway logs
            console.log("Found User Role:", findUser.role);

            if (findUser.role && findUser.role.trim().toLowerCase() === 'admin') {
                const checkPassword = bcrypt.compareSync(password, findUser.password)
                
                if (checkPassword) {
                    const userToken = jwt.sign({ id: findUser._id }, process.env.TOKEN_SECRET_KEY);
                    res.json({ message: 'success', userToken })
                } else {
                    res.json({ message: 'wrong password' })
                }
            } else {
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
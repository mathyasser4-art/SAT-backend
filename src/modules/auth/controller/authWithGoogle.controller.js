const userModel = require('../../../../DB/models/user.model')
const axios = require('axios');
const { issueToken } = require('../../../services/sessions');
const { normalizeEmail, emailQuery } = require('../../../services/accountGuard');

const authWithGoogle = async (req, res) => {
    try {
        const { access_token } = req.body
        const resData = await axios.get(
            `https://www.googleapis.com/oauth2/v3/userinfo?access_token=${access_token}`
        )
        const { data } = resData
        if (data) {
            const { email_verified, email } = data
            if (email_verified == true) {
                const findUser = await userModel.findOne({ email: emailQuery(email) })
                if (!findUser) {
                    const { name } = data
                    req.body.email = normalizeEmail(email)
                    req.body.userName = name
                    req.body.verify = true
                    const addUser = new userModel(req.body)
                    const userData = await addUser.save()
                    if (userData) {
                        const userToken = await issueToken(userData, req);
                        res.json({ message: 'success', userToken })
                    } else {
                        res.json({ message: 'Error... This account has not been registered to our servers. Please try again' })
                    }
                } else {
                    const userToken = await issueToken(findUser, req);
                    res.json({ message: 'success', userToken })
                }
            } else {
                res.json({ message: 'your google account is not verify' })
            }
        } else {
            res.json({ message: 'this access token is expired' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

module.exports = authWithGoogle
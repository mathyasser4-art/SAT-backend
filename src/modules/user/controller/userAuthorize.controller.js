const userModel = require('../../../../DB/models/user.model')
const { verifySessionToken } = require('../../../services/sessions');

const userAuthroize = async (req, res) => {
    try {
        const { userToken } = req.params
        const { id } = await verifySessionToken(req, userToken)
        const findUser = await userModel.findById(id).select('userName email role verify createdBy').populate({ path: 'createdBy', select: 'userName' })
        if (findUser) {
            if (findUser.verify) {
                res.json({ message: 'success', userInfo: findUser })
            } else {
                res.json({ message: 'this email is not verify' })
            }
        } else {
            res.json({ message: 'this email is not founed' })
        }
    } catch (error) {
        res.json({ message: error.message, code: error.code })
    }
}

module.exports = userAuthroize
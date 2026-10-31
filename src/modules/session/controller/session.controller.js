const mongoose = require('mongoose')
const userModel = require('../../../../DB/models/user.model')
const { listSessions, endUserSession } = require('../../../services/sessions')
const { buildStudentQuery } = require('../../student/controller/student.controller')

const currentId = (req) => req.session && req.session._id

// The devices this account is logged in on
const getMySessions = async (req, res) => {
    try {
        res.json({ message: 'success', ...(await listSessions(req.userData._id, { currentId: currentId(req) })) })
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
}

// Logs out one of my devices
const endMySession = async (req, res) => {
    try {
        const ended = await endUserSession(req.userData._id, req.params.sessionId, 'logout')
        res.json({ message: ended ? 'success' : 'This device is already logged out.' })
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
}

// Logs out the device sending this request (the Logout button), freeing its slot
const logout = async (req, res) => {
    try {
        if (req.session) await endUserSession(req.userData._id, req.session._id, 'logout')
        res.json({ message: 'success' })
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
}

// Staff can only see students they could see on the Students page
const findVisibleStudent = async (req) => {
    const { studentID } = req.params
    if (!mongoose.Types.ObjectId.isValid(studentID)) return null
    const query = await buildStudentQuery(req.userData, { _id: studentID })
    return userModel.findOne(query).select('userName').lean()
}

// A student's devices: logged in now, plus the last ones logged out
const getStudentSessions = async (req, res) => {
    try {
        const student = await findVisibleStudent(req)
        if (!student) return res.status(404).json({ message: 'Student not found' })
        res.json({ message: 'success', student, ...(await listSessions(student._id, { history: 10 })) })
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
}

// Logs a student out on one device, e.g. one they lost or someone else is using
const endStudentSession = async (req, res) => {
    try {
        const student = await findVisibleStudent(req)
        if (!student) return res.status(404).json({ message: 'Student not found' })
        const ended = await endUserSession(student._id, req.params.sessionId, 'staff')
        res.json({ message: ended ? 'success' : 'This device is already logged out.' })
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
}

module.exports = { getMySessions, endMySession, logout, getStudentSessions, endStudentSession }

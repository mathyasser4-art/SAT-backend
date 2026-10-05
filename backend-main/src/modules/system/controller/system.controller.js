const systemModel = require('../../../../DB/models/system.model')
const subjectModel = require('../../../../DB/models/subject.model')
const unitModel = require('../../../../DB/models/unit.model')

const addSystem = async (req, res) => {
    try {
        const addSystem = new systemModel(req.body)
        await addSystem.save()
        const allSystem = await systemModel.find().populate('subjects')
        res.json({ message: "success", allSystem })
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getAllSystem = async (req, res) => {
    try {
        const { questionTypeID } = req.params
        let query = {}
        
        // If questionTypeID is provided, filter by it
        if (questionTypeID) {
            query.questionTypeID = questionTypeID
        }
        
        const allSystem = await systemModel.find(query).populate('subjects')
        if (allSystem.length != 0) {
            res.json({ message: "success", allSystem })
        } else {
            res.json({ message: "There are no system now." })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const updateSystem = async (req, res) => {
    try {
        const { systemID } = req.params
        const updateSystem = await systemModel.findByIdAndUpdate(systemID, req.body)
        if (updateSystem) {
            const allSystem = await systemModel.find().populate('subjects')
            res.json({ message: "success", allSystem })
        } else {
            res.json({ message: "an error is happend." })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const deleteSystem = async (req, res) => {
    try {
        const { systemID } = req.params
        const findSystem = await systemModel.findById(systemID)
        if (findSystem) {
            if (findSystem.subjects && findSystem.subjects.length > 0) {
                // Delete all units associated with these subjects
                await unitModel.deleteMany({ subject: { $in: findSystem.subjects } })
                // Delete all subjects belonging to this system
                await subjectModel.deleteMany({ _id: { $in: findSystem.subjects } })
            }
            await systemModel.findByIdAndDelete(systemID)
            const allSystem = await systemModel.find().populate('subjects')
            res.json({ message: "success", allSystem })
        } else {
            res.status(404).json({ message: "This system id is wrong" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

module.exports = { addSystem, getAllSystem, updateSystem, deleteSystem }
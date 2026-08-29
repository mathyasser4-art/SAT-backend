const schoolSubjectModel = require('../../../../DB/models/schoolSubject.model');
const { getSchoolHierarchy } = require('../../../services/schoolContext');

const buildSubjectQuery = (associatedIds) => {
    return {
        $or: [
            { school: { $in: associatedIds } },
            { createdBy: { $in: associatedIds } },
            { school: { $exists: false } },
            { school: null }
        ]
    };
};

const getSchoolSubject = async (req, res) => {
    try {
        const { associatedIds } = await getSchoolHierarchy(req.userData);
        const allSubject = await schoolSubjectModel.find(buildSubjectQuery(associatedIds));
        if (allSubject && allSubject.length !== 0) {
            res.json({ message: "success", allSubject });
        } else {
            res.json({ message: "There is no any subject yet.", allSubject: [] });
        }
    } catch (error) {
        console.error('getSchoolSubject error:', error);
        res.status(502).json({ message: error.message });
    }
};

const addSchoolSubject = async (req, res) => {
    try {
        const { schoolSubjectName } = req.body;
        const { schoolId, associatedIds } = await getSchoolHierarchy(req.userData);
        const findSubject = await schoolSubjectModel.findOne({ 
            schoolSubjectName: { $regex: new RegExp(`^${schoolSubjectName.trim()}$`, 'i') }, 
            ...buildSubjectQuery(associatedIds) 
        });

        if (findSubject) {
            res.json({ message: "This subject has been added before" });
        } else {
            req.body.school = schoolId;
            req.body.createdBy = req.userData._id;
            const addSubject = new schoolSubjectModel(req.body);
            const subjectData = await addSubject.save();
            if (subjectData) {
                const allSubject = await schoolSubjectModel.find(buildSubjectQuery(associatedIds));
                res.json({ message: "success", allSubject: allSubject || [] });
            } else {
                res.json({ message: "an error is happend" });
            }
        }
    } catch (error) {
        console.error('addSchoolSubject error:', error);
        res.status(502).json({ message: error.message });
    }
};

const updateSchoolSubject = async (req, res) => {
    try {
        const { subjectID } = req.params;
        const findSubject = await schoolSubjectModel.findById(subjectID);
        if (findSubject) {
            const { associatedIds } = await getSchoolHierarchy(req.userData);
            const updateSubject = await schoolSubjectModel.findByIdAndUpdate(subjectID, req.body, { new: true });
            if (updateSubject) {
                const allSubject = await schoolSubjectModel.find(buildSubjectQuery(associatedIds));
                res.json({ message: "success", allSubject: allSubject || [] });
            } else {
                res.json({ message: "an error is happend" });
            }
        } else {
            res.json({ message: "There is no subject with this id" });
        }
    } catch (error) {
        console.error('updateSchoolSubject error:', error);
        res.status(502).json({ message: error.message });
    }
};

const removeSchoolSubject = async (req, res) => {
    try {
        const { subjectID } = req.params;
        const findSubject = await schoolSubjectModel.findById(subjectID);
        if (findSubject) {
            const { associatedIds } = await getSchoolHierarchy(req.userData);
            const removeSubject = await schoolSubjectModel.findByIdAndDelete(subjectID);
            if (removeSubject) {
                const allSubject = await schoolSubjectModel.find(buildSubjectQuery(associatedIds));
                res.json({ message: "success", allSubject: allSubject || [] });
            } else {
                res.json({ message: "an error is happend" });
            }
        } else {
            res.json({ message: "There is no subject with this id" });
        }
    } catch (error) {
        console.error('removeSchoolSubject error:', error);
        res.status(502).json({ message: error.message });
    }
};

module.exports = { addSchoolSubject, updateSchoolSubject, removeSchoolSubject, getSchoolSubject };
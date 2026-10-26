const classModel = require('../../../../DB/models/class.model');
const userModel = require('../../../../DB/models/user.model');
const courseModel = require('../../../../DB/models/course.model');
const assignmentModel = require('../../../../DB/models/assignment.model');
const { getSchoolHierarchy } = require('../../../services/schoolContext');
const { ToolError, isId } = require('./util');

// Same list the assignment controller treats as privileged
const PRIVILEGED_ROLES = ['Admin', 'School', 'Supervisor', 'IT'];

// Everything the teacher is allowed to see through the Copilot. Every tool goes through this,
// so a teacher can never reach another teacher's or another school's students.
class TeacherScope {
    constructor(user) {
        this.user = user;
        this.userId = String(user._id);
        this.isPrivileged = PRIVILEGED_ROLES.includes(user.role);
        this.loaded = null;
    }

    async load() {
        if (this.loaded) return this.loaded;
        this.loaded = (async () => {
            const me = this.user._id;
            const conditions = [{ teachers: me }, { createdBy: me }];
            const fresh = await userModel.findById(me).select('classList').lean();
            if (fresh && Array.isArray(fresh.classList) && fresh.classList.length > 0) {
                conditions.push({ _id: { $in: fresh.classList } });
            }
            if (this.isPrivileged) {
                const { associatedIds } = await getSchoolHierarchy(this.user);
                if (associatedIds.length > 0) {
                    conditions.push({ school: { $in: associatedIds } }, { createdBy: { $in: associatedIds } });
                }
            }
            const classes = await classModel.find({ $or: conditions }).select('class school teachers').lean();
            // Only what the tools need from each session, not every student's uploaded PDF
            const courses = await courseModel.find({ teacher: me })
                .select('name students sessions._id sessions.title sessions.order sessions.date sessions.onlineHw sessions.onlineClasswork').lean();

            this.classes = classes;
            this.classIds = new Set(classes.map(c => String(c._id)));
            this.courses = courses;
            this.courseStudentIds = new Set(courses.flatMap(c => (c.students || []).map(String)));
            this.courseAssignmentIds = new Set(courses.flatMap(c => (c.sessions || []).flatMap(s => [
                ...(s.onlineHw || []), ...(s.onlineClasswork || [])
            ]).map(String)));
            return this;
        })();
        return this.loaded;
    }

    // Drops the cached lists after a change, so the next check sees it
    forget() {
        this.loaded = null;
    }

    className(id) {
        const found = (this.classes || []).find(c => String(c._id) === String(id));
        return found ? found.class : null;
    }

    // Only the course's own teacher, the same rule the course controller applies to every change
    requireCourse(courseId) {
        const course = isId(courseId) && (this.courses || []).find(c => String(c._id) === String(courseId));
        if (!course) throw new ToolError(`Course "${courseId}" is not one of yours. Use list_my_classes to get the right id.`);
        return course;
    }

    // The teacher's courses that have this assignment on one of their sessions
    coursesWith(assignmentId) {
        const id = String(assignmentId);
        return (this.courses || []).filter(c => (c.sessions || []).some(s => [
            ...(s.onlineHw || []), ...(s.onlineClasswork || [])
        ].map(String).includes(id)));
    }

    // Students in the teacher's classes or courses
    studentFilter(extra = {}) {
        const classIds = [...this.classIds];
        return {
            role: 'Student',
            disable: { $ne: true },
            $or: [
                { class: { $in: classIds } },
                { classList: { $in: classIds } },
                { _id: { $in: [...this.courseStudentIds] } },
            ],
            ...extra,
        };
    }

    async requireStudent(studentId) {
        await this.load();
        if (!isId(studentId)) throw new ToolError(`"${studentId}" is not a valid student id. Use list_students to find it.`);
        const student = await userModel.findOne(this.studentFilter({ _id: studentId }))
            .select('userName email phone parentName parentPhone class classList').lean();
        if (!student) throw new ToolError('That student is not in any of your classes or courses.');
        return student;
    }

    requireClass(classId) {
        if (!isId(classId) || !this.classIds.has(String(classId))) {
            throw new ToolError(`Class "${classId}" is not one of your classes. Use list_my_classes to get the right id.`);
        }
        return classId;
    }

    canSeeAssignment(assignment) {
        if (String(assignment.createdBy) === this.userId) return true;
        if (this.courseAssignmentIds.has(String(assignment._id))) return true;
        return (assignment.classes || []).some(c => this.classIds.has(String(c._id || c)));
    }

    // Mirrors updateAssignment: the creator, or a privileged role whose school owns every class on it
    canChangeAssignment(assignment) {
        if (String(assignment.createdBy) === this.userId) return true;
        if (this.courseAssignmentIds.has(String(assignment._id))) return true;
        const classes = assignment.classes || [];
        return this.isPrivileged && classes.length > 0 && classes.every(c => this.classIds.has(String(c._id || c)));
    }

    // Mirrors deleteAssignment, which (unlike edits) gives course membership no rights
    canDeleteAssignment(assignment) {
        if (String(assignment.createdBy) === this.userId) return true;
        const classes = assignment.classes || [];
        return this.isPrivileged && classes.length > 0 && classes.every(c => this.classIds.has(String(c._id || c)));
    }

    async requireAssignment(assignmentId, { forChange = false, forDelete = false } = {}) {
        await this.load();
        if (!isId(assignmentId)) throw new ToolError(`"${assignmentId}" is not a valid assignment id. Use list_assignments to find it.`);
        const assignment = await assignmentModel.findById(assignmentId).lean();
        if (!assignment || !this.canSeeAssignment(assignment)) throw new ToolError('That assignment is not one of yours.');
        if (forChange && !this.canChangeAssignment(assignment)) throw new ToolError('You can view this assignment but only its creator can change it.');
        if (forDelete && !this.canDeleteAssignment(assignment)) throw new ToolError('You can view this assignment but only its creator can delete it.');
        return assignment;
    }
}

module.exports = { TeacherScope, PRIVILEGED_ROLES };

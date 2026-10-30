// Per-student order for assignments with `shuffle` on. The order is seeded by student,
// assignment and trial, so a reload or another device shows the same order, while
// classmates (and the student's next trial) get a different one.

// FNV-1a: string -> 32-bit seed
const seedOf = (text) => {
    let h = 2166136261
    for (let i = 0; i < text.length; i++) {
        h ^= text.charCodeAt(i)
        h = Math.imul(h, 16777619)
    }
    return h >>> 0
}

// mulberry32: small seeded random number generator
const randomFrom = (seed) => () => {
    seed = (seed + 0x6D2B79F5) >>> 0
    let t = seed
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
}

const shuffled = (list, key) => {
    const out = [...list]
    const random = randomFrom(seedOf(key))
    for (let i = out.length - 1; i > 0; i--) {
        const j = Math.floor(random() * (i + 1))
        ;[out[i], out[j]] = [out[j], out[i]]
    }
    return out
}

const keyOf = (assignment, studentID, attempt) => `${String(studentID)}:${String(assignment._id)}:${Number(attempt) || 1}`

// The assignment's questions (ids or docs) in the order this student sees them on this trial
const questionOrderFor = (assignment, studentID, attempt) => {
    const questions = (assignment.questions || []).filter(Boolean)
    return assignment.shuffle ? shuffled(questions, `${keyOf(assignment, studentID, attempt)}:questions`) : questions
}

const isFilled = (v) => v !== null && v !== undefined && String(v).trim() !== ''

// MCQ choices in this student's order. The homework page shows the first four unique
// choices, so those four are shuffled and nothing else, keeping the correct one in the list.
const choicesFor = (question, assignment, studentID, attempt) => {
    const choices = Array.from(new Set((question.wrongAnswer || []).filter(isFilled))).slice(0, 4)
    return shuffled(choices, `${keyOf(assignment, studentID, attempt)}:${String(question._id)}`)
}

module.exports = { questionOrderFor, choicesFor }

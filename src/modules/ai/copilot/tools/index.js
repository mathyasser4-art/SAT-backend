// Every Copilot tool, defined once. kind: 'read' runs right away; 'write' only prepares a change
// that the teacher must confirm. A read result may carry `ui` (buttons, a page to open) for the
// chat window, which is stripped before the result goes to Claude.
const students = require('./students');
const assignments = require('./assignments');
const questionBank = require('./questionBank');
const navigation = require('./navigation');
const courses = require('./courses');

// Course tools come last, right after get_course in navigation
const ALL_TOOLS = [...students.tools, ...assignments.tools, ...questionBank.tools, ...navigation.tools, ...courses.tools];
const TOOLS_BY_NAME = new Map(ALL_TOOLS.map(t => [t.name, t]));

// Definitions sent to Claude. Built once, in a fixed order, so the prompt cache prefix never changes.
const TOOL_DEFINITIONS = ALL_TOOLS.map(t => ({
    name: t.name,
    description: t.description,
    input_schema: t.input_schema,
    eager_input_streaming: true,
}));

module.exports = { TOOLS_BY_NAME, TOOL_DEFINITIONS };

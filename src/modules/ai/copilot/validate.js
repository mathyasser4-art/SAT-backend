// Checks a tool input against its JSON schema. Covers the subset the Copilot tools use:
// object, string, integer, number, boolean, array, enum, required, minimum/maximum, maxItems.
// Streamed tool inputs are not validated by the API, so nothing runs before this passes.
const typeOk = (value, type) => {
    switch (type) {
        case 'string': return typeof value === 'string';
        case 'integer': return Number.isInteger(value);
        case 'number': return typeof value === 'number' && Number.isFinite(value);
        case 'boolean': return typeof value === 'boolean';
        case 'array': return Array.isArray(value);
        case 'object': return value !== null && typeof value === 'object' && !Array.isArray(value);
        default: return true;
    }
};

const check = (value, schema, path, errors) => {
    if (schema.type && !typeOk(value, schema.type)) {
        errors.push(`${path} must be ${schema.type}`);
        return;
    }
    if (schema.enum && !schema.enum.includes(value)) errors.push(`${path} must be one of: ${schema.enum.join(', ')}`);
    if (typeof value === 'number') {
        if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path} must be at least ${schema.minimum}`);
        if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path} must be at most ${schema.maximum}`);
    }
    if (Array.isArray(value)) {
        if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${path} can have at most ${schema.maxItems} items`);
        if (schema.items) value.forEach((item, i) => check(item, schema.items, `${path}[${i}]`, errors));
    }
    if (schema.type === 'object') {
        const props = schema.properties || {};
        (schema.required || []).forEach(key => {
            if (value[key] === undefined) errors.push(`${path}.${key} is required`);
        });
        Object.keys(value).forEach(key => {
            if (props[key]) check(value[key], props[key], `${path}.${key}`, errors);
            else if (schema.additionalProperties === false) errors.push(`${path}.${key} is not a known field`);
        });
    }
};

const validateInput = (input, schema) => {
    const errors = [];
    check(input, schema, 'input', errors);
    return errors;
};

module.exports = { validateInput };

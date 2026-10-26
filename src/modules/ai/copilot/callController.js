// Runs an existing Express controller with the teacher's identity, so the Copilot goes through the
// same checks and logic as the website instead of a second copy of them.
const callController = (handler, { user, params = {}, body = {}, query = {} }, timeoutMs = 20000) => new Promise((resolve, reject) => {
    let statusCode = 200;
    let settled = false;
    const finish = (payload) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ status: statusCode, ok: statusCode < 400, body: payload });
    };
    const timer = setTimeout(() => {
        if (!settled) {
            settled = true;
            reject(new Error('The website did not answer in time.'));
        }
    }, timeoutMs);

    const req = { userData: user, params, body, query, headers: {} };
    const res = {
        status(code) { statusCode = code; return res; },
        json: finish,
        send: finish,
    };

    Promise.resolve()
        .then(() => handler(req, res))
        .catch(err => {
            if (!settled) {
                settled = true;
                clearTimeout(timer);
                reject(err);
            }
        });
});

module.exports = callController;

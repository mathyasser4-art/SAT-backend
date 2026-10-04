const https = require('https');

const targetId = '6aa2c24dec7ba02921a43504';

function getLiveDetails() {
    return new Promise((resolve, reject) => {
        https.get(`https://sat-backend-production.up.railway.app/question/getQuestionDetails/${targetId}`, res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(JSON.parse(data)));
        }).on('error', reject);
    });
}

async function run() {
    const res = await getLiveDetails();
    console.log('Live question status:', res.message);
    const q = res.question;
    console.log('Question ID:', q._id);
    console.log('Question:', q.question.substring(0, 100));
    console.log('Type:', q.typeOfAnswer);
    console.log('WrongAnswer length:', q.wrongAnswer.length);
    console.log('Choice 0 [A]:', q.wrongAnswer[0]);
    console.log('Choice 1 [B]:', q.wrongAnswer[1]);
}

run().catch(console.error);

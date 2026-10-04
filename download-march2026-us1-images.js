const https = require('https');
const fs = require('fs');

const images = [
    // Module 1
    { name: 'mar26_us1_m1_q1.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783729376/questionPic/ebhzlm51pngueiroz3ly.png' },
    { name: 'mar26_us1_m1_q2.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783729943/questionPic/rrh6xqouqr6hjhuiavoc.png' },
    { name: 'mar26_us1_m1_q4.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783730373/questionPic/su89kkweiikh38k8yjr1.png' },
    { name: 'mar26_us1_m1_q8.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783731550/questionPic/ep7tpng1bdfn7xyzh2ty.png' },
    { name: 'mar26_us1_m1_q13.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783734089/questionPic/nb2v2ig5kfseu9irq50g.png' },
    { name: 'mar26_us1_m1_q18.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783737720/questionPic/a4s2gun9f8v64ocgwuwj.png' },
    { name: 'mar26_us1_m1_q20.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783737990/questionPic/wybtyni354tjpse1fryf.png' },

    // Module 2
    { name: 'mar26_us1_m2_q6.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783782517/questionPic/ii1fdzqvjrkahiwmp666.png' },
    { name: 'mar26_us1_m2_q10.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783783387/questionPic/vhvwiau4py3wnl2m2zpl.png' },
    { name: 'mar26_us1_m2_q14.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783784324/questionPic/xt1ycntjiconljmawc91.png' },
    { name: 'mar26_us1_m2_q19.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783785497/questionPic/geqxki3cpqw9hdpe5hu3.png' }
];

function download(item) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(item.name);
        https.get(item.url, res => {
            res.pipe(file);
            file.on('finish', () => {
                file.close(() => resolve(item.name));
            });
        }).on('error', reject);
    });
}

async function run() {
    for (const img of images) {
        process.stdout.write(`Downloading ${img.name}... `);
        await download(img);
        console.log('Done.');
    }
    console.log('All 11 images downloaded!');
}

run().catch(console.error);

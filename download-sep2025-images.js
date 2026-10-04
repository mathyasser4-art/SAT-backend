const https = require('https');
const fs = require('fs');
const path = require('path');

const images = [
    { name: 'm1_q2_6a685934c3d08d90637d3b6f.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785223476/questionPic/vtdcij1b2ozoo4ud59wf.png' },
    { name: 'm1_q16_6a686698c3d08d90637d3bd2.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785226903/questionPic/rg0ggz2weaiwlqxpdwkq.png' },
    { name: 'm1_q20_6a686b1cc3d08d90637d3bf0.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785228059/questionPic/tqfqovtszloatzibw8os.png' },
    { name: 'm2_q22_6a688e61c3d08d90637d3c96.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785237089/questionPic/tkyhawydoh5yc2ermelg.png' },
    // Also M1 Q9 table images
    { name: 'm1_q9_choice_a.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785225644/quill-images/sazugihhpazjkuyotz78.png' },
    { name: 'm1_q9_choice_b.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785225616/quill-images/c0iiaexo5pcfucolseii.png' },
    { name: 'm1_q9_choice_c.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785225633/quill-images/luzaostpranjbvkm5ak3.png' },
    { name: 'm1_q9_choice_d.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785225657/quill-images/zntpmigf6sjjzmytm0ed.png' },
];

const destDir = path.join(__dirname, 'sep2025_original_images');
if (!fs.existsSync(destDir)) fs.mkdirSync(destDir);

images.forEach(img => {
    const file = fs.createWriteStream(path.join(destDir, img.name));
    https.get(img.url, res => {
        res.pipe(file);
        file.on('finish', () => {
            file.close();
            console.log(`Downloaded ${img.name}`);
        });
    }).on('error', err => {
        console.error(`Error downloading ${img.name}:`, err.message);
    });
});

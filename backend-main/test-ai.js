require('dotenv').config();
const { GoogleGenAI } = require('@google/genai');

async function test() {
    try {
        const ai = new GoogleGenAI({ apiKey: 'AIzaSyANSbsIZ05GhTXjPPYpBfodwakVy4wMVuA' });
        const response = await ai.models.generateContent({
            model: 'gemini-2.0-flash',
            contents: 'Hello',
        });
        console.log("Success:", response.text);
    } catch (err) {
        console.error("Error:", err);
    }
}
test();

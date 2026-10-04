const fs = require('fs');
const path = require('path');
const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const Q_TYPE_ID = '65a4963482dbaac16d820fc6';
const REAL_EXAMS_SYSTEM_ID = '69e7cbcac0cd6fbad9c578af';

function fetchJson(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    reject(new Error(`Failed parsing JSON: ${e.message}`));
                }
            });
        }).on('error', reject);
    });
}

const stripHtml = (str) => {
    if (!str) return '';
    return str.replace(/<[^>]+>/g, '')
              .replace(/&nbsp;/g, ' ')
              .replace(/&amp;/g, '&')
              .replace(/&lt;/g, '<')
              .replace(/&gt;/g, '>')
              .replace(/﻿/g, '')
              .replace(/\s+/g, ' ')
              .trim();
};

const extractImgSrc = (str) => {
    if (!str) return null;
    const match = str.match(/<img[^>]+src=["']([^"']+)["']/i);
    return match ? match[1] : null;
};

async function auditRealExamsAccurate() {
    console.log('🚀 Running refined audit for Real Exams (image-aware)...');
    const sysRes = await fetchJson(`${API_BASE}/system/getAllSystem`);
    const realSystem = sysRes.allSystem.find(s => s._id === REAL_EXAMS_SYSTEM_ID || s.systemName === 'Real Exams');

    let totalScanned = 0;
    const genuineIssues = [];

    for (const sub of realSystem.subjects) {
        const examName = sub.subjectName.trim();
        const unitsRes = await fetchJson(`${API_BASE}/unit/getUnit/${Q_TYPE_ID}/${sub._id}`);
        const units = unitsRes.allUnit || [];

        for (const u of units) {
            for (const ch of (u.chapters || [])) {
                const moduleName = ch.chapterName.trim();
                const chapRes = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${ch._id}`);
                const questions = chapRes.chapter?.questions || [];
                totalScanned += questions.length;

                questions.forEach((q, idx) => {
                    const qNum = idx + 1;
                    const qId = q._id;
                    const qType = q.typeOfAnswer;
                    const qIssues = [];

                    const rawQ = q.question || '';
                    const cleanQ = stripHtml(rawQ);

                    // 1. Broken angle brackets in question stem
                    if (rawQ.includes('>p>>span') || rawQ.includes('>span class=') || rawQ.includes('>>math')) {
                        qIssues.push({
                            type: 'CORRUPTED_HTML_IN_STEM',
                            detail: 'Question text contains corrupted angle brackets (>p>>span) leaking raw code'
                        });
                    }

                    // 2. Empty question
                    if (!cleanQ && !q.questionPic && !rawQ.includes('<img')) {
                        qIssues.push({
                            type: 'EMPTY_QUESTION',
                            detail: 'Question text and visuals are completely empty'
                        });
                    }

                    // 3. MCQ checks
                    if (qType === 'MCQ') {
                        const allChoices = q.wrongAnswer || [];

                        // Choices count
                        if (allChoices.length < 4) {
                            qIssues.push({
                                type: 'FEWER_THAN_4_CHOICES',
                                detail: `Only ${allChoices.length} choices found (should be 4)`
                            });
                        }

                        // Check duplicates (distinguishing between image choices vs text choices)
                        const choiceSignatures = allChoices.map((c, i) => {
                            const imgSrc = extractImgSrc(c);
                            if (imgSrc) return `IMG:${imgSrc}`;
                            const text = stripHtml(c);
                            return `TXT:${text}`;
                        });

                        for (let i = 0; i < choiceSignatures.length; i++) {
                            for (let j = i + 1; j < choiceSignatures.length; j++) {
                                if (choiceSignatures[i] === choiceSignatures[j]) {
                                    const sig = choiceSignatures[i];
                                    // If both are empty and no image, that's a true blank duplicate
                                    const desc = sig.startsWith('IMG:') ? `Image (${sig.substring(4, 50)}...)` : `Text ("${sig.substring(4, 50)}")`;
                                    qIssues.push({
                                        type: 'DUPLICATE_CHOICES',
                                        detail: `Choice ${String.fromCharCode(65 + i)} and Choice ${String.fromCharCode(65 + j)} are identical duplicates of ${desc}`
                                    });
                                }
                            }
                        }

                        // Check if any choice has broken HTML brackets
                        allChoices.forEach((c, cIdx) => {
                            if (c && (c.includes('>p>>span') || c.includes('>span class=') || c.includes('>>math'))) {
                                qIssues.push({
                                    type: 'CORRUPTED_HTML_IN_CHOICE',
                                    detail: `Choice ${String.fromCharCode(65 + cIdx)} has broken angle brackets leaking raw HTML/KaTeX markup`
                                });
                            }
                        });

                        // Check correct answer exists among choices
                        const rawCorrect = q.correctAnswer;
                        const cleanCorrect = stripHtml(rawCorrect);
                        const correctImg = extractImgSrc(rawCorrect);

                        if (!rawCorrect || (cleanCorrect === '' && !correctImg)) {
                            qIssues.push({
                                type: 'MISSING_CORRECT_ANSWER',
                                detail: 'Correct answer field is completely missing or blank'
                            });
                        } else {
                            let matchFound = false;
                            if (correctImg) {
                                matchFound = allChoices.some(c => extractImgSrc(c) === correctImg);
                            } else {
                                matchFound = allChoices.some(c => {
                                    const cleanC = stripHtml(c);
                                    return cleanC === cleanCorrect || cleanC.includes(cleanCorrect) || cleanCorrect.includes(cleanC);
                                });
                            }

                            if (!matchFound) {
                                qIssues.push({
                                    type: 'CORRECT_ANSWER_NOT_IN_CHOICES',
                                    detail: `Correct answer (${cleanCorrect.substring(0, 50)}) is not present in the 4 answer choices`
                                });
                            }
                        }
                    } else if (qType === 'Essay') {
                        // Fill-in-the-blank (SPR)
                        const answers = q.answer || [];
                        const validAnswers = answers.filter(a => a !== null && a !== undefined && String(a).trim() !== '');
                        if (validAnswers.length === 0) {
                            qIssues.push({
                                type: 'MISSING_ESSAY_ANSWER',
                                detail: 'No answer value provided in answer array for Student-Produced Response (Grid-in)'
                            });
                        }
                    }

                    // 4. Missing images when strongly referenced
                    const mentionsFig = (cleanQ.toLowerCase().includes('shown in the figure') ||
                                         cleanQ.toLowerCase().includes('the figure above') ||
                                         cleanQ.toLowerCase().includes('the figure below') ||
                                         cleanQ.toLowerCase().includes('the graph shown') ||
                                         cleanQ.toLowerCase().includes('shown in the graph') ||
                                         cleanQ.toLowerCase().includes('scatterplot shown') ||
                                         cleanQ.toLowerCase().includes('scatter plot shown') ||
                                         cleanQ.toLowerCase().includes('in the xy-plane above') ||
                                         cleanQ.toLowerCase().includes('table shown above'));

                    const hasImage = q.questionPic || rawQ.includes('<img') || rawQ.includes('data:image');
                    if (mentionsFig && !hasImage) {
                        qIssues.push({
                            type: 'POSSIBLE_MISSING_IMAGE',
                            detail: 'Question text references a figure/graph, but no image URL is attached'
                        });
                    }

                    if (qIssues.length > 0) {
                        genuineIssues.push({
                            examName,
                            moduleName,
                            qNum,
                            qId,
                            qType,
                            snippet: cleanQ.substring(0, 80),
                            issues: qIssues
                        });
                    }
                });
            }
        }
    }

    console.log(`\nScan Complete: ${totalScanned} questions scanned across all Real Exams.`);
    console.log(`Total Genuine Issues: ${genuineIssues.length}`);

    fs.writeFileSync(
        path.join(__dirname, 'real_exams_refined_issues.json'),
        JSON.stringify({ totalScanned, genuineIssues }, null, 2)
    );
}

auditRealExamsAccurate().catch(console.error);

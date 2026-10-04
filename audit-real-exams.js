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
                    reject(new Error(`Failed parsing JSON from ${url}: ${e.message}`));
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

async function auditRealExams() {
    console.log('🚀 Starting deep scan of REAL EXAMS...');
    const sysRes = await fetchJson(`${API_BASE}/system/getAllSystem`);
    const realSystem = sysRes.allSystem.find(s => s._id === REAL_EXAMS_SYSTEM_ID || s.systemName === 'Real Exams');
    
    if (!realSystem) {
        console.error('Real Exams system not found!');
        return;
    }

    console.log(`Found Real Exams: ${realSystem.subjects?.length} Exam Subjects.`);
    
    const allExamsData = [];
    let totalQuestionsCount = 0;
    const issues = [];

    for (let sIdx = 0; sIdx < realSystem.subjects.length; sIdx++) {
        const sub = realSystem.subjects[sIdx];
        const examName = sub.subjectName.trim();
        console.log(`[${sIdx + 1}/${realSystem.subjects.length}] Scanning: ${examName}...`);

        let unitsRes;
        try {
            unitsRes = await fetchJson(`${API_BASE}/unit/getUnit/${Q_TYPE_ID}/${sub._id}`);
        } catch (err) {
            console.error(`Error fetching units for ${examName}:`, err.message);
            continue;
        }

        const units = unitsRes.allUnit || [];
        for (const u of units) {
            const unitName = u.unitName.trim();
            for (const ch of (u.chapters || [])) {
                const moduleName = ch.chapterName.trim();
                let chapRes;
                try {
                    chapRes = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${ch._id}`);
                } catch (err) {
                    console.error(`Error fetching chapter ${ch._id}:`, err.message);
                    continue;
                }

                const questions = chapRes.chapter?.questions || [];
                totalQuestionsCount += questions.length;

                questions.forEach((q, qIdx) => {
                    const qNum = qIdx + 1;
                    const qId = q._id;
                    const qType = q.typeOfAnswer;
                    const qIssues = [];

                    const cleanQ = stripHtml(q.question);
                    const rawQ = q.question || '';

                    // 1. Corrupted angle brackets / raw HTML leak in question text
                    if (rawQ.includes('>p>>span') || rawQ.includes('>span class=') || rawQ.includes('>>math')) {
                        qIssues.push({
                            type: 'CORRUPTED_HTML_BRACKETS',
                            detail: 'Question stem contains broken angle brackets (>p>>span) leaking raw code to students'
                        });
                    }

                    // 2. Empty question text
                    if (!cleanQ || cleanQ.length < 3) {
                        qIssues.push({
                            type: 'EMPTY_QUESTION',
                            detail: `Question stem is effectively empty: "${cleanQ}"`
                        });
                    }

                    // 3. MCQ audits
                    if (qType === 'MCQ') {
                        const allChoices = q.wrongAnswer || [];
                        const cleanChoices = allChoices.map(stripHtml);
                        const cleanCorrect = stripHtml(q.correctAnswer);

                        // Fewer than 4 choices
                        if (allChoices.length < 4) {
                            qIssues.push({
                                type: 'FEWER_THAN_4_CHOICES',
                                detail: `Has only ${allChoices.length} choices instead of 4`
                            });
                        }

                        // Duplicate choices
                        for (let i = 0; i < cleanChoices.length; i++) {
                            for (let j = i + 1; j < cleanChoices.length; j++) {
                                if (cleanChoices[i] && cleanChoices[j] && cleanChoices[i] === cleanChoices[j] && cleanChoices[i] !== '.') {
                                    qIssues.push({
                                        type: 'DUPLICATE_CHOICES',
                                        detail: `Choice ${String.fromCharCode(65 + i)} and Choice ${String.fromCharCode(65 + j)} are identical duplicates ("${cleanChoices[i].substring(0, 50)}")`
                                    });
                                }
                            }
                        }

                        // Corrupted brackets in choices
                        allChoices.forEach((c, cIdx) => {
                            if (c && (c.includes('>p>>span') || c.includes('>span class=') || c.includes('>>math'))) {
                                qIssues.push({
                                    type: 'CORRUPTED_HTML_IN_CHOICE',
                                    detail: `Choice ${String.fromCharCode(65 + cIdx)} has broken angle brackets leaking raw HTML/KaTeX markup`
                                });
                            }
                        });

                        // Correct answer not in choices array
                        if (cleanCorrect) {
                            const exactOrLoose = cleanChoices.some(c => c === cleanCorrect || (c && cleanCorrect && (c.includes(cleanCorrect) || cleanCorrect.includes(c))));
                            if (!exactOrLoose && cleanCorrect.length > 1) {
                                qIssues.push({
                                    type: 'CORRECT_ANSWER_NOT_IN_CHOICES',
                                    detail: `Correct answer "${cleanCorrect.substring(0, 60)}" is not among the options`
                                });
                            }
                        } else {
                            qIssues.push({
                                type: 'MISSING_CORRECT_ANSWER',
                                detail: 'Correct answer field is completely blank or missing'
                            });
                        }
                    } else if (qType === 'Essay') {
                        // Essay / Grid-In answer check
                        const answers = q.answer || [];
                        const cleanAnswers = answers.filter(a => a !== null && a !== undefined && String(a).trim() !== '');
                        if (cleanAnswers.length === 0) {
                            qIssues.push({
                                type: 'MISSING_ESSAY_ANSWER',
                                detail: 'No answer value provided in answer array for Student-Produced Response (Grid-in)'
                            });
                        }
                    }

                    // 4. Broken image / missing figure
                    const mentionsFig = (cleanQ.toLowerCase().includes('shown in the figure') ||
                                         cleanQ.toLowerCase().includes('the figure above') ||
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
                            detail: 'Question text explicitly references a graph/figure/table, but no image or diagram is attached'
                        });
                    }

                    if (qIssues.length > 0) {
                        issues.push({
                            examName,
                            unitName,
                            moduleName,
                            qNum,
                            qId,
                            qType,
                            cleanQuestionSnippet: cleanQ.substring(0, 100),
                            issues: qIssues
                        });
                    }
                });
            }
        }
    }

    console.log('\n=======================================');
    console.log('AUDIT FINISHED!');
    console.log(`Total Real Exam Questions Scanned: ${totalQuestionsCount}`);
    console.log(`Total Questions with Issues: ${issues.length}`);
    console.log('=======================================\n');

    const outPath = path.join(__dirname, 'real_exams_audit_results.json');
    fs.writeFileSync(outPath, JSON.stringify({ totalQuestionsCount, issues }, null, 2));
    console.log(`Saved results to: ${outPath}`);
}

auditRealExams().catch(console.error);

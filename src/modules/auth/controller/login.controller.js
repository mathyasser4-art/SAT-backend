const userModel = require('../../../../DB/models/user.model');
const classModel = require('../../../../DB/models/class.model');
const sendEmail = require('../../../services/sendEmail');
const generateCode = require('../../../services/generateVerificationCode');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const getJwtSecret = require('../../../services/jwtSecret');
const { emailQuery } = require('../../../services/accountGuard');

// Multi-tenant Domain Registry: maps teacher or school identifiers to custom branded domains.
// Future schools/teachers can be added here or set directly in user.customDomain.
const DOMAIN_REGISTRY = [
    { match: 'shahin', domain: 'mrshahin.com' },
    { match: 'arrowad', domain: 'ais.satarea.tech' },
    { match: 'ais', domain: 'ais.satarea.tech' }
];

const resolveCustomDomain = async (user) => {
    if (!user) return { targetDomain: null, teacherName: '' };

    // 1. Explicit customDomain defined on user record
    if (user.customDomain) {
        return { targetDomain: user.customDomain, teacherName: user.userName };
    }

    const userNameLower = (user.userName || '').toLowerCase();
    const emailLower = (user.email || '').toLowerCase();
    const schoolNameLower = (user.createdBy?.userName || '').toLowerCase();

    // 2. Direct match for Teacher or School accounts
    if (user.role === 'Teacher' || user.role === 'School') {
        for (const entry of DOMAIN_REGISTRY) {
            if (userNameLower.includes(entry.match) || emailLower.includes(entry.match) || schoolNameLower.includes(entry.match)) {
                return { targetDomain: entry.domain, teacherName: user.userName };
            }
        }
        return { targetDomain: null, teacherName: user.userName };
    }

    // 3. For Student accounts, resolve teacher affiliation via their assigned class
    if (user.role === 'Student') {
        let teacherName = '';
        let targetDomain = null;

        const classIds = [];
        if (user.class) classIds.push(user.class);
        if (Array.isArray(user.classList) && user.classList.length > 0) {
            classIds.push(...user.classList);
        }

        if (classIds.length > 0) {
            try {
                const studentClasses = await classModel.find({ _id: { $in: classIds } }).populate('teachers', 'userName email customDomain');
                for (const cls of studentClasses) {
                    if (Array.isArray(cls.teachers)) {
                        for (const teacher of cls.teachers) {
                            if (teacher && teacher.userName) {
                                teacherName = teacher.userName;
                                if (teacher.customDomain) {
                                    targetDomain = teacher.customDomain;
                                    break;
                                }
                                const tName = teacher.userName.toLowerCase();
                                const tEmail = (teacher.email || '').toLowerCase();
                                for (const entry of DOMAIN_REGISTRY) {
                                    if (tName.includes(entry.match) || tEmail.includes(entry.match)) {
                                        targetDomain = entry.domain;
                                        break;
                                    }
                                }
                            }
                            if (targetDomain) break;
                        }
                    }
                    if (targetDomain) break;
                }
            } catch (e) {
                console.error('Error resolving student domain:', e);
            }
        }

        // Check if school name also matches
        if (!targetDomain && schoolNameLower) {
            for (const entry of DOMAIN_REGISTRY) {
                if (schoolNameLower.includes(entry.match)) {
                    targetDomain = entry.domain;
                    break;
                }
            }
        }

        return { targetDomain, teacherName };
    }

    return { targetDomain: null, teacherName: '' };
};

const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const cleanPhone = (email || '').toString().trim();
        const rawDigits = cleanPhone.replace(/\D/g, '');
        let queryMatches = await userModel.find({
            $or: [
                { 'email': email },
                { 'userName': email },
                { 'phone': email },
                ...(cleanPhone ? [{ 'phone': cleanPhone }] : []),
                ...(rawDigits ? [{ 'email': `${rawDigits}@satarea.user` }] : [])
            ]
        }).populate('createdBy', 'userName');

        // Emails are now saved lowercased; still match accounts regardless of casing
        if (queryMatches.length === 0 && cleanPhone.includes('@')) {
            queryMatches = await userModel.find({ email: emailQuery(cleanPhone) }).populate('createdBy', 'userName');
        }

        // Prioritize institutional roles over general guest 'User' to ensure enrolled students always log into their class account
        const rolePriority = { 'Teacher': 1, 'School': 2, 'Admin': 3, 'IT': 4, 'Supervisor': 5, 'Student': 6, 'Parent': 7, 'User': 8 };
        queryMatches.sort((a, b) => (rolePriority[a.role] || 99) - (rolePriority[b.role] || 99));
        const findUser = queryMatches[0] || null;

        if (findUser) {
            if (!findUser.verify) {
                findUser.verificationCode = generateCode();
                await findUser.save();
                const emailMessage = `<div style="direction: rtl; padding: 10px 30px;">
                    <p style="font-size: 20px; font-weight: bold; color: #000;">Welcome, ${findUser.fullName || findUser.userName}. We are happy that you have registered with us. Your account verification code is</p>
                    <p style="font-size: 40px; font-weight: bold; color: #000;">${findUser.verificationCode}</p>
                    </div>`;
                // `email` is whatever was typed to log in (it can be a username or phone number)
                sendEmail(findUser.email || email, emailMessage, 'Account verification', 'Practice Papers');
                res.json({ message: 'this account is not verify check your email to get your code verification', isVerify: false });
            } else {
                let checkPassword = await bcrypt.compare(password, findUser.password);

                if (!checkPassword && findUser.password === password) {
                    const saltRounds = parseInt(process.env.SALTROUNDS) || 10;
                    const hashedPassword = await bcrypt.hash(password, saltRounds);
                    await userModel.updateOne({ _id: findUser._id }, { $set: { password: hashedPassword } });
                    checkPassword = true;
                }

                if (checkPassword) {
                    const userToken = jwt.sign({ id: findUser._id }, getJwtSecret());
                    const schoolName = findUser.role === 'School' 
                        ? findUser.userName 
                        : (findUser.createdBy?.userName || 'SAT School');

                    const { targetDomain, teacherName } = await resolveCustomDomain(findUser);

                    let trialStart = findUser.trialStartDate;
                    let trialExpires = findUser.trialExpiresAt;
                    if (findUser.role === 'User' && !trialExpires) {
                        trialStart = findUser.createdAt || new Date();
                        trialExpires = new Date(new Date(trialStart).getTime() + 7 * 24 * 60 * 60 * 1000);
                        await userModel.updateOne(
                            { _id: findUser._id }, 
                            { $set: { trialStartDate: trialStart, trialExpiresAt: trialExpires } }
                        );
                    }

                    res.json({ 
                        message: 'success', 
                        userToken, 
                        userName: findUser.userName, 
                        role: findUser.role,
                        id: findUser._id,
                        email: findUser.email,
                        schoolName: schoolName,
                        teacherName: teacherName || '',
                        targetDomain: targetDomain || null,
                        trialStartDate: trialStart,
                        trialExpiresAt: trialExpires,
                        isSubscribed: findUser.isSubscribed || false
                    });
                } else {
                    res.json({ message: 'wrong password' });
                }
            }
        } else {
            res.json({ message: 'this email or username is not registered' });
        }
    } catch (error) {
        console.error('login error:', error);
        res.status(502).json({ message: error.message });
    }
};

module.exports = login;
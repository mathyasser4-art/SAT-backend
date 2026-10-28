const express = require('express')
// Express 4 ignores the promise an async route returns, so an error thrown in one went
// unhandled and Node 20 shut the whole server down. This passes it to the error handler
// at the bottom of this file instead. It must be required before any router is created.
require('express-async-errors')
const app = express()
require('dotenv').config()

// Last line of defence for promises nobody awaits (fire-and-forget calls): log the error
// instead of letting Node exit and drop every student's in-flight request.
process.on('unhandledRejection', (reason) => {
    console.error('Unhandled promise rejection:', reason);
});

if (!process.env.TOKEN_SECRET_KEY && process.env.JWT_SECRET) {
    console.warn('TOKEN_SECRET_KEY is missing, falling back to JWT_SECRET');
    process.env.TOKEN_SECRET_KEY = process.env.JWT_SECRET;
}

// Validate SALTROUNDS environment variable
const saltRounds = parseInt(process.env.SALTROUNDS);
if (isNaN(saltRounds) || saltRounds < 1) {
    console.warn('Invalid or missing SALTROUNDS environment variable, using default value of 10');
    process.env.SALTROUNDS = 10;
}

const cors = require('cors')

// CORS Configuration - Allow requests from frontend domains
const whitelist = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : [
      'https://mrshahin.com',
      'https://www.mrshahin.com',
      'https://satarea.tech',
      'https://www.satarea.tech',
      'http://localhost:3000'
    ];

const isAllowedOrigin = (origin) => {
  if (!origin) {
    return true;
  }

  if (whitelist.includes(origin)) {
    return true;
  }

  try {
    const parsedOrigin = new URL(origin);
    const isLocalhost =
      (parsedOrigin.hostname === 'localhost' || parsedOrigin.hostname === '127.0.0.1' || parsedOrigin.hostname.startsWith('192.168.')) &&
      ['http:', 'https:'].includes(parsedOrigin.protocol);
    
    const isVercel = parsedOrigin.hostname.endsWith('.vercel.app');
    const isRailway = parsedOrigin.hostname.endsWith('.railway.app');
    const isMrShahin = parsedOrigin.hostname === 'mrshahin.com' || parsedOrigin.hostname.endsWith('.mrshahin.com');
    const isSatArea = parsedOrigin.hostname === 'satarea.tech' || parsedOrigin.hostname.endsWith('.satarea.tech');

    return isLocalhost || isVercel || isRailway || isMrShahin || isSatArea;
  } catch (error) {
    return false;
  }
};

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, Postman, or same-origin)
    if (isAllowedOrigin(origin)) {
      callback(null, true)
    } else {
      console.log('Blocked by CORS:', origin);
      callback(new Error('Not allowed by CORS'))
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'authorization', 'auth-token', 'authrization', 'token']
};

app.use(cors(corsOptions));
const port = process.env.PORT || 3000;
// 50mb is required: the frontend uploads homework/course PDFs as base64 JSON.
app.use(express.json({ limit: '50mb' }))
app.use(express.urlencoded({ extended: true, limit: '50mb' }))

// Performance & Security Middlewares
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');

// API-only server: allow our responses/files to be used by the frontend on another domain.
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false,
}));
// Blocks Mongo operator injection ($gt, $ne, ...) while keeping dotted keys intact.
app.use(mongoSanitize({ allowDots: true }));
app.use(compression());

// Fix for Railway proxy + express-rate-limit ERR_ERL_UNEXPECTED_X_FORWARDED_FOR
app.set('trust proxy', 1);

const connectionDB = require('./DB/connection')
connectionDB().catch((error) => {
    // No connection string is configured: stop, so the deploy shows as crashed instead of
    // running with no database (the unhandledRejection logger above would hide this).
    console.error(error.message);
    process.exit(1);
});

// Rate limiting
// Whole classrooms often share ONE school IP, so the global limit must be generous.
const rateLimit = require('express-rate-limit');
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1500,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'OPTIONS' || req.path === '/health',
  message: { message: 'Too many requests, please try again in a minute' },
});
// Strict brute-force protection on login/register: only FAILED attempts are counted.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { message: 'Too many failed login attempts, please try again in 15 minutes' },
});
app.use(globalLimiter);
app.use(['/auth/login', '/auth/register', '/auth/google'], authLimiter);

const { authRouter, userRouter, systemRouter, questionTypeRouter, unitRouter, chapterRouter, questionRouter, adminRouter, subjectRouter, classRouter, schoolRouter, schoolSubjectRouter, teacherRouter, studentRouter, assignmentRouter, answerRouter, itRouter, supervisorRouter, uploadRouter, courseRouter, practiceRouter, parentRouter, journeyRouter, aiRouter, questionReportRouter, videoRouter, liveRouter } = require('./router/allRoutes');
app.use(authRouter, userRouter, systemRouter, questionTypeRouter, unitRouter, chapterRouter, questionRouter, adminRouter, subjectRouter, classRouter, schoolRouter, schoolSubjectRouter, teacherRouter, studentRouter, assignmentRouter, answerRouter, itRouter, supervisorRouter, uploadRouter, courseRouter, practiceRouter, parentRouter, journeyRouter, aiRouter, questionReportRouter, videoRouter, liveRouter);

const CronJob = require('cron').CronJob;
const { startHwCleanupCron } = require('./src/services/hwCleanupCron');
startHwCleanupCron();

// Health check endpoint
app.get('/health', async (req, res) => {
    const mongoose = require('mongoose');
    const dbState = mongoose.connection.readyState;
    const states = {
        0: 'disconnected',
        1: 'connected',
        2: 'connecting',
        3: 'disconnecting'
    };
    
    if (dbState === 1) {
        res.status(200).json({ 
            status: 'healthy', 
            database: states[dbState],
            timestamp: new Date().toISOString()
        });
    } else {
        res.status(503).json({ 
            status: 'unhealthy', 
            database: states[dbState],
            timestamp: new Date().toISOString()
        });
    }
});

app.get('/', (req, res) => res.send('Hello World!'))

// Any error a route throws or passes to next() ends here, so the client always gets JSON
// (the frontend reads `message`) instead of an HTML page or a request that never answers.
app.use((err, req, res, next) => {
    console.error(`${req.method} ${req.originalUrl} failed:`, err);
    if (res.headersSent) return next(err);
    const status = err.status || err.statusCode || 500;
    res.status(status >= 400 && status < 600 ? status : 500).json({ message: err.message || 'Something went wrong, please try again' });
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}!`);
});

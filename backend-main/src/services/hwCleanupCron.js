const CronJob = require('cron').CronJob;
const courseModel = require('../../DB/models/course.model');
const cloudinary = require('cloudinary').v2;
const cloudinaryConfig = require('./cloudinary');
cloudinaryConfig();

/**
 * Scans all course sessions for student homework submissions older than `retentionDays`
 * (default: 60 days), deletes the PDF asset from Cloudinary to reclaim storage,
 * and sets `fileUrl = 'EXPIRED'` while preserving the student submission record.
 */
const cleanupOldHwSubmissions = async (retentionDays = 60) => {
    try {
        console.log(`[hwCleanupCron] Running daily cleanup for submissions older than ${retentionDays} days...`);
        const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

        const courses = await courseModel.find({
            "sessions.studentHwSubmissions": {
                $elemMatch: {
                    submittedAt: { $lt: cutoffDate },
                    publicId: { $exists: true, $ne: null }
                }
            }
        });

        let totalPurged = 0;

        for (const course of courses) {
            let courseModified = false;

            if (Array.isArray(course.sessions)) {
                for (const session of course.sessions) {
                    if (Array.isArray(session.studentHwSubmissions)) {
                        for (const sub of session.studentHwSubmissions) {
                            if (sub.submittedAt && sub.submittedAt < cutoffDate && sub.publicId) {
                                try {
                                    await cloudinary.uploader.destroy(sub.publicId, { resource_type: 'raw' });
                                    await cloudinary.uploader.destroy(sub.publicId, { resource_type: 'image' });
                                } catch (cloudErr) {
                                    console.warn(`[hwCleanupCron] Failed to destroy Cloudinary asset ${sub.publicId}:`, cloudErr.message);
                                }
                                sub.fileUrl = 'EXPIRED';
                                sub.publicId = null;
                                courseModified = true;
                                totalPurged++;
                            }
                        }
                    }
                }
            }

            if (courseModified) {
                await course.save();
            }
        }

        console.log(`[hwCleanupCron] Cleanup complete. Purged ${totalPurged} expired submission PDFs.`);
        return totalPurged;
    } catch (err) {
        console.error('[hwCleanupCron] Error during homework PDF cleanup:', err.message);
        return 0;
    }
};

/**
 * Initializes and starts the daily cron job (runs every day at 03:00 AM UTC).
 */
const startHwCleanupCron = () => {
    try {
        const job = new CronJob('0 3 * * *', async () => {
            await cleanupOldHwSubmissions(60);
        }, null, true, 'UTC');

        console.log('[hwCleanupCron] Scheduled daily homework PDF cleanup job (03:00 AM UTC, 60-day retention).');
        return job;
    } catch (cronErr) {
        console.error('[hwCleanupCron] Failed to schedule cron job:', cronErr.message);
    }
};

module.exports = {
    startHwCleanupCron,
    cleanupOldHwSubmissions
};

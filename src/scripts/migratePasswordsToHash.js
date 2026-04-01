/**
 * Migration Script: Hash plain text passwords
 *
 * Finds all users whose passwords are stored as plain text (i.e. not a bcrypt
 * hash) and re-saves them as properly hashed values.
 *
 * Usage:
 *   ONLINE_CONNECTION_DB=<uri> SALTROUNDS=10 node src/scripts/migratePasswordsToHash.js
 *
 * Safe to run multiple times — already-hashed passwords are skipped.
 */

require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const BCRYPT_PREFIXES = ['$2a$', '$2b$', '$2y$'];

const isBcryptHash = (password) => {
    if (!password || typeof password !== 'string') return false;
    return BCRYPT_PREFIXES.some((prefix) => password.startsWith(prefix));
};

async function migratePasswords() {
    const connectionString = process.env.ONLINE_CONNECTION_DB;
    if (!connectionString) {
        console.error('ERROR: ONLINE_CONNECTION_DB environment variable is not set.');
        process.exit(1);
    }

    const saltRounds = parseInt(process.env.SALTROUNDS);
    if (isNaN(saltRounds) || saltRounds < 1) {
        console.error('ERROR: SALTROUNDS environment variable is missing or invalid.');
        process.exit(1);
    }

    console.log('Connecting to MongoDB...');
    await mongoose.connect(connectionString);
    console.log('Connected.');

    // Dynamically require the model after the connection is established so
    // Mongoose registers it against the correct connection.
    const userModel = require('../../DB/models/user.model');

    // Fetch all users that have a password field set
    const users = await userModel.find({ password: { $exists: true, $ne: null } });
    console.log(`Total users with a password field: ${users.length}`);

    let migratedCount = 0;
    let skippedCount = 0;

    for (const user of users) {
        if (isBcryptHash(user.password)) {
            skippedCount++;
            continue;
        }

        // Plain text password — hash it
        const hashed = await bcrypt.hash(user.password, saltRounds);
        await userModel.updateOne({ _id: user._id }, { $set: { password: hashed } });
        migratedCount++;
        console.log(`  Migrated user: ${user.email || user.userName} (${user._id})`);
    }

    console.log('');
    console.log('Migration complete.');
    console.log(`  Users migrated : ${migratedCount}`);
    console.log(`  Users skipped  : ${skippedCount} (already hashed)`);

    await mongoose.disconnect();
    console.log('Disconnected from MongoDB.');
}

migratePasswords().catch((err) => {
    console.error('Migration failed:', err);
    process.exit(1);
});

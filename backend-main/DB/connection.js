const mongoose = require('mongoose');

const connectionDB = () => {
    const uri = process.env.ONLINE_CONNECTION_DB || 
                process.env.DATABASE_URL || 
                process.env.MONGODB_URI || 
                process.env.MONGO_URI;

    if (!uri) {
        console.error('❌ MongoDB Connection Error: No connection string provided. Please set ONLINE_CONNECTION_DB or DATABASE_URL or MONGODB_URI environment variable.');
        return Promise.reject(new Error('Missing MongoDB connection string'));
    }

    console.log('Connecting to MongoDB database...');
    const connectionPromise = mongoose.connect(uri)
        .then(() => {
            console.log('✅ Connection db is running successfully...');
        })
        .catch((error) => {
            console.error('❌ An error happened in connection db:', error.message);
        });
    
    return connectionPromise;
}

module.exports = connectionDB
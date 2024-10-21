import express from 'express';
import connectDB, { IDBConfig } from './config/db';
import authRoutes from './routes/authRoutes';
import dotenv from 'dotenv';
import cron from 'node-cron';
import { cleanExpiredSessions } from './utils/sessionCleanup';

dotenv.config();

const app = express();

const dbConfig: IDBConfig = {
   mongoURL: process.env.MONGO_URL || '',
};

// Schedule a job to run every minute to clean up expired sessions
cron.schedule('* * * * *', async () => {
   await cleanExpiredSessions();
   console.log('Session cleanup job ran');
});

connectDB(dbConfig)
   .then(() => {
      console.log('Database connection established.');
   })
   .catch((error: string) => {
      console.error('Error connecting to the database:', error);
   });

app.use(express.json());

app.use('/api/auth', authRoutes);

export default app;

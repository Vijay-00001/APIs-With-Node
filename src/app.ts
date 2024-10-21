import express from 'express';
import connectDB, { IDBConfig } from './config/db';
import authRoutes from './routes/authRoutes';
import dotenv from 'dotenv';
import cron from 'node-cron';
import { cleanExpiredSessions } from './utils/sessionCleanup';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

dotenv.config();

const app = express();

// Helmet for security
app.use(helmet());

// Enable CORS for handling multiple origins
app.use(
   cors({
      origin: process.env.ALLOWED_ORIGINS?.split(',') || '*', // You can list specific origins for production
      methods: 'GET,POST,PUT,DELETE',
      allowedHeaders: 'Content-Type,Authorization',
   })
);

// Rate limiting to handle many requests and prevent abuse
const limiter = rateLimit({
   windowMs: 15 * 60 * 1000, // 15 minutes
   max: 100, // Limit each IP to 100 requests per windowMs
   message: 'Too many requests from this IP, please try again later',
});

// Apply the rate limiter to all requests
app.use(limiter);

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

// Use auth routes
app.use('/api/auth', authRoutes);

export default app;

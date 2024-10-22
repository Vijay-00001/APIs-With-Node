import express from 'express';
import connectDB, { IDBConfig } from './config/db';
import authRoutes from './routes/authRoutes';
import dotenv from 'dotenv';
import cron from 'node-cron';
import { cleanExpiredSessions } from './utils/sessionCleanup';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import hpp from 'hpp';
import compression from 'compression';
import fs from 'fs';
import https from 'https';
import morgan from 'morgan';
import path from 'path';

dotenv.config();

const app = express();

// Enable HTTPS in production (assuming you have SSL certificates)
if (process.env.NODE_ENV === 'production') {
   const privateKey = fs.readFileSync(
      path.join(__dirname, 'ssl', 'private.key'),
      'utf8'
   );
   const certificate = fs.readFileSync(
      path.join(__dirname, 'ssl', 'certificate.crt'),
      'utf8'
   );
   const ca = fs.readFileSync(
      path.join(__dirname, 'ssl', 'ca_bundle.crt'),
      'utf8'
   );

   const credentials = { key: privateKey, cert: certificate, ca };
   const httpsServer = https.createServer(credentials, app);
   httpsServer.listen(443, () => {
      console.log('HTTPS Server running on port 443');
   });
}

// Set up security-related HTTP headers
app.use(helmet());

// Define CORS settings
app.use(
   cors({
      origin:
         process.env.NODE_ENV === 'development'
            ? '*'
            : process.env.ALLOWED_ORIGINS?.split(','),
      methods: 'GET,POST,PUT,DELETE',
      allowedHeaders: 'Content-Type,Authorization',
   })
);

// Rate limiting to prevent abuse (e.g., DDoS attacks)
const limiter = rateLimit({
   windowMs: 15 * 60 * 1000, // 15 minutes
   max: 100, // Limit each IP to 100 requests per windowMs
   message: 'Too many requests from this IP, please try again later',
});
app.use(limiter);

// Input sanitization to prevent NoSQL injection
app.use(mongoSanitize()); // Sanitize data to prevent MongoDB injection attacks

// Prevent HTTP parameter pollution
app.use(hpp()); // Prevent multiple query parameters with the same name (HTTP parameter pollution)

// Compression middleware to improve performance
app.use(compression()); // Compress responses to reduce payload size

// Basic request logging
app.use(morgan('combined')); // Log requests to the console for better tracking

// Setup database connection
const dbConfig: IDBConfig = {
   mongoURL: process.env.MONGO_URL || '',
};

// Schedule a job to clean expired sessions every minute
cron.schedule('* * * * *', async () => {
   await cleanExpiredSessions();
   console.log('Session cleanup job ran');
});

// Connect to MongoDB
connectDB(dbConfig)
   .then(() => {
      console.log('Database connection established.');
   })
   .catch((error: string) => {
      console.error('Error connecting to the database:', error);
   });

// Middleware to parse incoming requests with JSON payloads
app.use(express.json());

// Mount auth routes
app.use('/api/auth', authRoutes);

// Error handling middleware
app.use(
   (
      err: any,
      req: express.Request,
      res: express.Response,
      next: express.NextFunction
   ) => {
      console.error(err.stack);
      res.status(500).json({
         error: 'Something went wrong, please try again later',
      });
   }
);

export default app;

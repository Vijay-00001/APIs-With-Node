import express from 'express';
import connectDB, { IDBConfig } from './config/db';
import authRoutes from './routes/authRoutes';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

const dbConfig: IDBConfig = {
   mongoURL: process.env.MONGO_URL || '',
};

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

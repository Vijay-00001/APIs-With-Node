import mongoose from 'mongoose';

export interface IDBConfig {
   mongoURL: string;
}

const connectDB: any = async ({ mongoURL }: IDBConfig): Promise<void> => {
   try {
      await mongoose.connect(mongoURL);
      console.log('MongoDB connected');
   } catch (err) {
      console.error('MongoDB connection error:', err);
      process.exit(1);
   }
};

export default connectDB;

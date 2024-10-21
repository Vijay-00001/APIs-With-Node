import mongoose from 'mongoose';

export interface IDBConfig {
   mongoURL: string;
}

const connectDB: any = async ({ mongoURL }: IDBConfig): Promise<void> => {
   const options: any = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
   };

   try {
      await mongoose.connect(mongoURL, options);
      console.log('MongoDB connected');
   } catch (err) {
      console.error('MongoDB connection error:', err);
      process.exit(1);
   }
};

export default connectDB;

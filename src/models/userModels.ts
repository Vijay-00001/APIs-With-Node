import mongoose, { Document, ObjectId, Schema } from 'mongoose';

export interface IUser extends Document {
   name: string;
   email: string;
   password: string;
   role: 'USER' | 'ADMIN';
   emailVerified: boolean;
   image?: string;
   createdAt: Date;
   _id: ObjectId;
}

const userSchema: Schema = new mongoose.Schema({
   name: { type: String, required: true },
   email: { type: String, required: true, unique: true },
   password: { type: String, required: true },
   role: { type: String, enum: ['USER', 'ADMIN'], default: 'USER' },
   emailVerified: { type: Boolean, default: false },
   image: { type: String },
   createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model<IUser>('User', userSchema);

export default User;

import mongoose, { Document, ObjectId, Schema } from 'mongoose';

export interface IUser extends Document {
   id: string;
   name: string;
   email: string;
   password: string;
   role: 'USER' | 'ADMIN';
   emailVerified: boolean;
   image?: string;
   createdAt: Date;
   lastLoginAt: Date;
   lastLogoutAt: Date;
   isDeleted: boolean;
   mailSentCount: number;
   lastMailSent: Date;
   _id: ObjectId;
}

const userSchema: Schema = new mongoose.Schema({
   id: { type: String, alias: '_id' }, // Alias for _id to make both same
   name: { type: String, required: true },
   email: { type: String, required: true, unique: true },
   password: { type: String, required: true },
   role: { type: String, enum: ['USER', 'ADMIN'], default: 'USER' },
   emailVerified: { type: Boolean, default: false },
   image: { type: String },
   createdAt: { type: Date, default: Date.now },
   lastLoginAt: { type: Date },
   lastLogoutAt: { type: Date },
   isDeleted: { type: Boolean, default: true },
   mailSentCount: { type: Number, default: 0 },
   lastMailSent: { type: Date },
});

// Middleware to set the id field equal to _id when creating a new user
userSchema.pre<IUser>('save', function (this: IUser, next) {
   if (!this.id) {
      this.id = this._id.toString(); // Make sure both _id and id are the same
   }
   next();
});

const User = mongoose.model<IUser>('User', userSchema);

export default User;

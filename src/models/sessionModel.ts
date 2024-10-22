import mongoose, { Schema, Document } from 'mongoose';
import { IUser } from './userModels'; // Import User interface if necessary

export interface ISession extends Document {
   sessionToken: string;
   userId: string;
   expiresAt: Date;
   user: IUser;
}

const sessionSchema: Schema = new Schema(
   {
      sessionToken: {
         type: String,
         unique: true,
         required: true,
         index: true, // You can add indexing for faster queries on the sessionToken
      },
      userId: {
         type: Schema.Types.ObjectId,
         ref: 'User', // Referencing the User model
         required: true,
      },
      expiresAt: {
         type: Date,
         required: true,
      },
   },
   {
      timestamps: true, // Automatically adds createdAt and updatedAt fields
      collection: 'sessions', // Map to the collection name "sessions"
   }
);

// Create and export the Session model
const Session = mongoose.model<ISession>('Session', sessionSchema);

export default Session;

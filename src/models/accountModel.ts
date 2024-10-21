import mongoose, { Schema, Document } from 'mongoose';

// Define the interface for the Account document
export interface IAccount extends Document {
   userId: Schema.Types.ObjectId; // References User schema
   type: string;
   provider: string;
   providerAccountId: string;
   refresh_token?: string;
   access_token?: string;
   expires_at?: number;
   token_type?: string;
   scope?: string;
   id_token?: string;
   session_state?: string;
}

// Define the Account schema
const accountSchema: Schema = new Schema(
   {
      userId: {
         type: Schema.Types.ObjectId,
         ref: 'User', // References User model
         required: true,
      },
      type: {
         type: String,
         required: true,
      },
      provider: {
         type: String,
         required: true,
      },
      providerAccountId: {
         type: String,
         required: true,
         unique: true, // Ensures no duplicate provider account IDs
      },
      refresh_token: String,
      access_token: String,
      expires_at: Number,
      token_type: String,
      scope: String,
      id_token: String,
      session_state: String,
   },
   {
      timestamps: true, // Automatically creates createdAt and updatedAt fields
      collection: 'accounts', // Specifies the collection name
   }
);

// Create a unique index on provider and providerAccountId
accountSchema.index({ provider: 1, providerAccountId: 1 }, { unique: true });

const Account = mongoose.model<IAccount>('Account', accountSchema);

export default Account;

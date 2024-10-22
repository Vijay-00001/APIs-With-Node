import mongoose, { Schema, Document } from 'mongoose';

export interface IVerificationToken extends Document {
   identifier: string;
   token: string;
   code: number;
   expiresAt: Date;
}

const verificationTokenSchema: Schema = new Schema({
   identifier: { type: String, required: true },
   token: { type: String, required: true, unique: true },
   code: { type: Number, require: true },
   expiresAt: { type: Date, required: true },
});

const VerificationToken = mongoose.model<IVerificationToken>(
   'VerificationToken',
   verificationTokenSchema
);

export default VerificationToken;

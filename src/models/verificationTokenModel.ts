import mongoose, { Schema, Document } from 'mongoose';

export interface IVerificationToken extends Document {
   identifier: string;
   token: string;
   expires: Date;
}

const verificationTokenSchema: Schema = new Schema({
   identifier: { type: String, required: true },
   token: { type: String, required: true, unique: true },
   expires: { type: Date, required: true },
});

const VerificationToken = mongoose.model<IVerificationToken>(
   'VerificationToken',
   verificationTokenSchema
);

export default VerificationToken;

// models/ForgotToken.ts
import mongoose, { Document, Model, Schema } from 'mongoose';

export interface IForgotToken extends Document {
   userId: mongoose.Types.ObjectId;
   token: string;
   createdAt: Date;
   expiresAt: Date;
}

const forgotTokenSchema: Schema<IForgotToken> = new Schema({
   userId: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
   token: { type: String, required: true },
   createdAt: { type: Date, default: Date.now },
   expiresAt: { type: Date, required: true, index: true },
});

const ForgotToken: Model<IForgotToken> = mongoose.model<IForgotToken>(
   'ForgotToken',
   forgotTokenSchema
);
export default ForgotToken;

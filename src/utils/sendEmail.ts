import nodemailer from 'nodemailer';
import { IUser } from '../models/userModels'; // Adjust this import path as needed
import dotenv from 'dotenv';

dotenv.config();

// Configure your email transporter (this is just an example, adjust accordingly)
// Configure nodemailer for email sending
const transporter = nodemailer.createTransport({
   host: 'smtp.ethereal.email',
   port: 587,
   auth: {
      user: 'darren81@ethereal.email',
      pass: 'RBm7nS7R6BN47NF1JY',
   },
});

/**
 * Sends a verification email to the user with the verification token.
 * @param user - The user object.
 * @param token - The verification token.
 */
export const sendVerificationEmail: any = async (
   user: IUser,
   token: string
): Promise<void> => {
   const verificationUrl = `${process.env.BASE_URL}/verify-email?token=${token}`;

   const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Verify your email address',
      html: `<p>Please verify your email by clicking on the following link: <a href="${verificationUrl}">Verify Email</a></p>`,
   };

   try {
      await transporter.sendMail(mailOptions);
      console.log(`Verification email sent to ${user.email}`);
   } catch (error) {
      console.error('Error sending verification email:', error);
      throw new Error('Error sending verification email');
   }
};

// utils/sendResetPasswordEmail.ts
export const sendResetPasswordEmail = async (user: IUser, token: string) => {
   const resetUrl = `${process.env.BASE_URL}/reset-password?token=${token}`;

   const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Password Reset Request',
      html: `<p>You requested a password reset. Click the link below to reset your password:</p>
             <p><a href="${resetUrl}">${resetUrl}</a></p>
             <p>This link will expire in 1 hour.</p>`,
   };

   try {
      await transporter.sendMail(mailOptions);
   } catch (error) {
      console.error('Error sending password reset email:', error);
      throw new Error('Error sending password reset email');
   }
};

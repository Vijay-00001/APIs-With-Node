import nodemailer from 'nodemailer';
import { IUser } from '../models/userModels'; // Adjust this import path as needed

// Configure your email transporter (this is just an example, adjust accordingly)
// Configure nodemailer for email sending
const transporter = nodemailer.createTransport({
   // host: 'smtp.ethereal.email',
   // port: 587,
   // auth: {
   //    user: process.env.EMAIL_USER as string,
   //    pass: process.env.EMAIL_PASS as string,
   // },
   host: 'smtp.ethereal.email',
   port: 587,
   auth: {
      user: 'veronica85@ethereal.email',
      pass: 'uysYSec7MAePMyZbMt',
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
   const verificationUrl = `http://localhost:3000/api/auth/verify-email?token=${token}`;

   const mailOptions = {
      from: 'owner@example.email',
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

import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import User, { IUser } from '../models/userModels';
import VerificationToken, {
   IVerificationToken,
} from '../models/verificationTokenModel';
import { generateToken } from '../config/jwt';
import Session, { ISession } from '../models/sessionModel';
import dns from 'dns';

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

// Register a new user
export const register: any = async (
   req: Request,
   res: Response
): Promise<void | any> => {
   const { name, email, password } = req.body;

   try {
      // Check if the user already exists
      const existingUser: IUser | null = await User.findOne({ email });

      if (existingUser) {
         // Check if the user has verified their email
         const existingVerificationToken: IVerificationToken | null =
            await VerificationToken.findOne({ identifier: email });

         if (
            existingVerificationToken &&
            existingVerificationToken.expires > new Date()
         ) {
            return res.status(400).json({
               error: 'User already registered and verification email already sent. Please check your inbox.',
            });
         }

         // If the email is not verified, resend the verification email
         if (!existingUser.emailVerified) {
            const verificationToken: string = crypto
               .randomBytes(32)
               .toString('hex');
            const expires: Date = new Date();
            expires.setHours(expires.getHours() + 1); // Token valid for 1 hour

            const newVerificationToken = new VerificationToken({
               identifier: existingUser.email,
               token: verificationToken,
               expires,
            });

            await VerificationToken.findOneAndUpdate(
               { identifier: email },
               { token: verificationToken, expires },
               { upsert: true }
            );

            const verificationUrl: string = `http://localhost:3000/api/auth/verify-email?token=${verificationToken}`;
            await transporter.sendMail({
               from: 'owner@example.email',
               to: existingUser.email,
               subject: 'Resend: Verify your email address',
               html: `<p>Please verify your email by clicking on the following link: <a href="${verificationUrl}">Verify Email</a></p>`,
            });

            return res.status(200).json({
               message: 'Verification email resent. Please check your inbox.',
            });
         }

         // If the email is already verified
         return res.status(400).json({
            error: 'Email already verified. Please log in.',
         });
      }

      // If the user doesn't exist, create a new user
      const hashedPassword = await bcrypt.hash(password, 10);

      const user: IUser = new User({
         name,
         email,
         password: hashedPassword,
         role: 'USER',
      });

      await user.save();

      // Generate verification token
      const verificationToken: string = crypto.randomBytes(32).toString('hex');
      const expires: Date = new Date();
      expires.setHours(expires.getHours() + 1); // Token valid for 1 hour

      const newVerificationToken: IVerificationToken = new VerificationToken({
         identifier: user.email,
         token: verificationToken,
         expires,
      });

      await newVerificationToken.save();

      // Send verification email
      const verificationUrl: string = `http://localhost:3000/api/auth/verify-email?token=${verificationToken}`;
      await transporter.sendMail({
         from: 'owner@example.email',
         to: user.email,
         subject: 'Verify your email address',
         html: `<p>Please verify your email by clicking on the following link: <a href="${verificationUrl}">Verify Email</a></p>`,
      });

      res.status(201).json({
         message: 'User registered. Verification email sent.',
      });
   } catch (error) {
      res.status(400).json({
         error: 'User registration failed',
         details: error,
      });
   }
};

// Verify user email
export const verifyEmail = async (
   req: Request,
   res: Response
): Promise<void> => {
   const { token } = req.query;

   try {
      const verificationToken = await VerificationToken.findOne({
         token: token as string,
      });

      if (!verificationToken || verificationToken.expires < new Date()) {
         res.status(400).json({
            error: 'Invalid or expired verification token',
         });
         return;
      }

      const user = await User.findOne({ email: verificationToken.identifier });
      if (!user) {
         res.status(404).json({ error: 'User not found' });
         return;
      }

      user.emailVerified = true;
      await user.save();

      await VerificationToken.deleteOne({ token: token as string });

      // Redirect the user to the login page after successful verification
      res.redirect('/login'); // or whatever the login route is
   } catch (error) {
      res.status(500).json({
         error: 'Email verification failed',
         details: error,
      });
   }
};

// Login user
export const login = async (req: Request, res: Response): Promise<void> => {
   const { email, password }: { email: string; password: string } = req.body;

   try {
      // Find the user by email
      const user: IUser | null = await User.findOne({ email });

      // If the user is not found or the password is incorrect
      if (!user || !(await bcrypt.compare(password, user.password))) {
         res.status(401).json({ error: 'Invalid credentials' });
         return;
      }

      // Check if the user's email has been verified
      if (!user.emailVerified) {
         res.status(403).json({
            error: 'Email not verified. Please verify your email to log in.',
         });
         return;
      }

      // Generate a session token (JWT or another form of token)
      const sessionToken = generateToken({
         _id: user._id.toString(),
         role: user.role,
      });

      // Set expiration date for the session (e.g., 24 hours)
      const expires = new Date();
      expires.setHours(expires.getHours() + 24);

      // Create a new session
      const session: ISession = new Session({
         sessionToken,
         userId: user._id,
         expires,
      });

      await session.save();

      // Respond with the session token and user data
      res.status(200).json({
         token: sessionToken,
         user: {
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
         }, // Send user data without sensitive info
         message: 'Login successful. Redirecting...',
         redirectUrl: '/dashboard', // Redirect URL
      });
   } catch (error) {
      // Handle login failure
      res.status(500).json({ error: 'Login failed', details: error });
   }
};

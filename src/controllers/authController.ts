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

// Configure nodemailer for email sending
const transporter = nodemailer.createTransport({
   service: 'gmail',
   auth: {
      user: process.env.EMAIL_USER as string,
      pass: process.env.EMAIL_PASS as string,
   },
});

// Register a new user
export const register = async (req: Request, res: Response): Promise<void> => {
   const { name, email, password } = req.body;

   try {
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

      res.status(200).json({ message: 'Email verified successfully' });
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
      const user: IUser | null = await User.findOne({ email });
      if (!user || !(await bcrypt.compare(password, user.password))) {
         res.status(401).json({ error: 'Invalid credentials' });
         return;
      }

      // Generate a session token
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

      res.status(200).json({ token: sessionToken, user });
   } catch (error) {
      res.status(500).json({ error: 'Login failed', details: error });
   }
};

import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import User, { IUser } from '../models/userModels';
import VerificationToken, {
   IVerificationToken,
} from '../models/verificationTokenModel';
import { generateToken } from '../config/jwt';
import Session, { ISession } from '../models/sessionModel';
import { sendVerificationEmail } from '../utils/sendVerificationEmail';

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

         // Check if the user is soft deleted
         if (existingUser.isDeleted) {
            const now = new Date();
            const mailResendWindow = 60 * 60 * 1000; // 1 hour in milliseconds
            const mailSentLimit = 3;

            // Ensure that we track when the email was last sent and how many times
            if (!existingUser.lastMailSent || !existingUser.mailSentCount) {
               existingUser.lastMailSent = now;
               existingUser.mailSentCount = 0;
            }

            // Check if the last email sent was within the time window
            if (
               now.getTime() - existingUser.lastMailSent.getTime() >
               mailResendWindow
            ) {
               // Reset the counter after the window expires
               existingUser.mailSentCount = 0;
            }

            // Check if the user has exceeded the email resend limit
            if (existingUser.mailSentCount >= mailSentLimit) {
               return res.status(429).json({
                  error: 'You have exceeded the maximum number of email resends. Please try again later.',
               });
            }

            // Resend the verification email if the limit has not been reached
            const verificationToken: string = crypto
               .randomBytes(32)
               .toString('hex');
            const expires: Date = new Date();
            expires.setHours(expires.getHours() + 1); // Token valid for 1 hour

            await VerificationToken.findOneAndUpdate(
               { identifier: email },
               { token: verificationToken, expires },
               { upsert: true }
            );

            await sendVerificationEmail(existingUser, verificationToken);

            // Update the user's mailSentCount and lastMailSent timestamp
            existingUser.mailSentCount += 1;
            existingUser.lastMailSent = now;
            await existingUser.save();

            return res.status(200).json({
               message: 'Verification email resent. Please check your inbox.',
            });
         }

         // If the user is not deleted, but email is not verified
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

            await sendVerificationEmail(existingUser, verificationToken);

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
         isDeleted: true, // Mark the account as soft deleted until email verification
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
      await sendVerificationEmail(existingUser, verificationToken);

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
      user.isDeleted = false; // Activate the account by marking it as not deleted
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
      const user = await User.findOne({ email });

      // If user not found or password incorrect
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

      // Check if a session exists for the user
      let session = await Session.findOne({ userId: user._id });

      const currentDateTime = new Date();

      // If session exists but expired, remove the old session
      if (session && session.expires < currentDateTime) {
         await Session.findByIdAndDelete(session._id); // Delete expired session
         session = null; // Set session to null to create a new one
      }

      // If no session exists, create a new session
      if (!session) {
         // Generate a session token (JWT or another form of token)
         const sessionToken = generateToken({
            _id: user._id.toString(),
            role: user.role,
         });

         // Set expiration date for the session (e.g., 24 hours)
         const expires = new Date();
         expires.setHours(expires.getHours() + 24);

         // Create a new session
         session = new Session({
            sessionToken,
            userId: user._id,
            expires,
         });

         await session.save();
      }

      // Update the user's last login time
      user.lastLoginAt = currentDateTime;
      await user.save();

      // Respond with the session token and user data
      res.status(200).json({
         token: session.sessionToken,
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

// Controller for user logout
export const logout: any = async (
   req: Request,
   res: Response
): Promise<void | any> => {
   try {
      // Get the session token from the request (usually from the authorization header or cookies)
      const sessionToken = req.headers.authorization?.split(' ')[1]; // If using Bearer token format

      if (!sessionToken) {
         return res.status(400).json({ message: 'No session token provided' });
      }

      // Find the session
      const session = await Session.findOne({ sessionToken });

      if (!session) {
         return res.status(404).json({ message: 'Session not found' });
      }

      // Update the user's lastLogoutAt field
      const user = await User.findById(session.userId);
      if (user) {
         user.lastLogoutAt = new Date(); // Set current date and time for last logout
         await user.save(); // Save the updated user document
      }

      // Delete the session
      await Session.findOneAndDelete({ sessionToken });

      // Respond with a success message
      res.status(200).json({ message: 'Logout successful' });
   } catch (error) {
      res.status(500).json({
         error: 'Failed to logout user',
         details: error,
      });
   }
};

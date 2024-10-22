import { Request, Response, NextFunction } from 'express';
import Session from '../models/sessionModel'; // Adjust the import path as necessary
import { verifyToken } from '../config/jwt'; // Adjust the import path as necessary

interface CustomRequest extends Request {
   user?: any; // You can specify the user type if you have a User interface
}

// Middleware to protect routes
export const protect: any = async (
   req: CustomRequest,
   res: Response,
   next: NextFunction
) => {
   const token = req.headers.authorization?.split(' ')[1];

   // Check for the JWT token
   if (!token) {
      return res.status(401).json({ error: 'Not authorized, no token' });
   }

   try {
      // Verify the JWT token
      const decoded = verifyToken(token);
      req.user = decoded; // Attach decoded user to request

      // Check if the session exists
      const session = await Session.findOne({
         sessionToken: token,
         userId: req.user.id,
         expiresAt: { $gt: new Date() },
      });

      if (!session) {
         return res
            .status(401)
            .json({ error: 'Not authorized, session not found' });
      }

      // If both checks pass, proceed to the next middleware
      next();
   } catch (error) {
      res.status(401).json({ error: 'Not authorized, invalid token' });
   }
};

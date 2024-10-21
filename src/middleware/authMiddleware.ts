import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../config/jwt';

export interface CustomRequest extends Request {
   user: any;
}

export const protect: any = (
   req: CustomRequest,
   res: Response,
   next: NextFunction
) => {
   const token = req.headers.authorization?.split(' ')[1];
   if (!token) {
      return res.status(401).json({ error: 'Not authorized, no token' });
   }

   try {
      const decoded = verifyToken(token);
      req.user = decoded; // Attach decoded user to request
      next();
   } catch (error) {
      res.status(401).json({ error: 'Not authorized, invalid token' });
   }
};

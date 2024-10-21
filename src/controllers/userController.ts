import { Request, Response, NextFunction } from 'express';
import { CustomRequest } from '../middleware/authMiddleware';

// Controller for fetching user profile
export const getProfile: any = async (
   req: CustomRequest,
   res: Response,
   next: NextFunction
): Promise<void> => {
   try {
      if (req.user) {
         res.status(200).json({
            success: true,
            user: req.user,
         });
      } else {
         res.status(404).json({
            success: false,
            error: 'User not found',
         });
      }
   } catch (error) {
      res.status(500).json({
         success: false,
         error: 'Internal server error',
      });
   }
   next();
};

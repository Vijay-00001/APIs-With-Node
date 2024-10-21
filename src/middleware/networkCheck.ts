// src/middlewares/networkCheck.ts
import { Request, Response, NextFunction } from 'express';
import { checkNetworkConnection } from '../utils/networkUtils';

interface CustomRequest extends Request {
   networkStatus: boolean;
}

export const networkCheck: any = async (
   req: CustomRequest,
   res: Response,
   next: NextFunction
) => {
   try {
      let isConnected = await checkNetworkConnection();

      // Store initial network status in request object
      req.networkStatus = isConnected;

      // If connected, proceed to the next middleware/controller
      if (isConnected) {
         console.log('Network connection available');
         return next();
      }

      // If not connected, check network status every 1 second
      const intervalId = setInterval(async () => {
         isConnected = await checkNetworkConnection();
         req.networkStatus = isConnected;

         if (isConnected) {
            console.log('Network connection available');

            clearInterval(intervalId); // Stop checking when connected
            next(); // Proceed to the next middleware/controller
         }
      }, 1000);

      // Optional: Set a timeout to stop checking after a certain time (e.g., 30 seconds)
      setTimeout(() => {
         clearInterval(intervalId);
         return res.status(503).json({
            error: 'Network connection unavailable after multiple attempts. Please try again later.',
         });
      }, 30000); // Stop checking after 30 seconds
   } catch (error) {
      return res
         .status(500)
         .json({ error: 'Failed to check network status', details: error });
   }
};

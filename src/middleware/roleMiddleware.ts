import { NextFunction, Request, Response } from 'express';

export const authorize = (
   roles: string[]
): ((
   req: Request,
   res: Response,
   next: NextFunction
) => Response<any, Record<string, any>> | undefined) => {
   return (
      req: Request,
      res: Response,
      next: NextFunction
   ): Response<any, Record<string, any>> | undefined => {
      if (!roles.includes((req as any).user.role)) {
         return res
            .status(403 as number)
            .json({ error: 'Forbidden: Insufficient role' });
      }
      next();
   };
};

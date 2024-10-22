import jwt, { JwtPayload } from 'jsonwebtoken';
import { decryptData, encryptData } from '../utils/security';

export interface ITokenPayload extends JwtPayload {
   id: string;
   role: string;
}

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

export const generateToken = (user: { _id: string; role: string }): string => {
   const jwtToken = jwt.sign(
      { id: user._id, role: user.role } as ITokenPayload,
      JWT_SECRET,
      { expiresIn: '1d' } // Token expires in 1 day
   );

   const token = encryptData(jwtToken);

   return token;
};

export const verifyToken = (token: string): ITokenPayload => {
   if (!token) {
      throw new Error('No token provided');
   }

   const decryptedToken = decryptData(token);

   return jwt.verify(decryptedToken, JWT_SECRET) as ITokenPayload;
};

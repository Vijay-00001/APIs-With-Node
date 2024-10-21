import jwt, { JwtPayload } from 'jsonwebtoken';

export interface ITokenPayload extends JwtPayload {
   id: string;
   role: string;
}

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

export const generateToken = (user: { _id: string; role: string }): string => {
   return jwt.sign(
      { id: user._id, role: user.role } as ITokenPayload,
      JWT_SECRET,
      { expiresIn: '1d' } // Token expires in 1 day
   );
};

export const verifyToken = (token: string): ITokenPayload => {
   return jwt.verify(token, JWT_SECRET) as ITokenPayload;
};

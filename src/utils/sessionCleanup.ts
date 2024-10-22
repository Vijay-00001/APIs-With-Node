import Session from '../models/sessionModel';
import VerificationToken from '../models/verificationTokenModel';
import ForgotToken from '../models/forgotTokenModel';

export const cleanExpiredSessions = async () => {
   try {
      const now = new Date();
      // Delete all sessions that have expired
      await Session.deleteMany({ expires: { $lt: now } });
      // Delete all verification tokens that have expired
      await VerificationToken.deleteMany({ expires: { $lt: now } });
      // Delete all forgot password tokens that have expired
      await ForgotToken.deleteMany({ expiresAt: { $lt: now } });
      console.log(
         'Expired sessions, verification tokens, and forgot password tokens cleaned up successfully.'
      );
   } catch (error) {
      console.error(
         'Error cleaning up expired sessions, verification tokens, and forgot password tokens:',
         error
      );
   }
};

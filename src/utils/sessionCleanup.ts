import Session from '../models/sessionModel';

export const cleanExpiredSessions = async () => {
   try {
      const now = new Date();
      // Delete all sessions that have expired
      await Session.deleteMany({ expires: { $lt: now } });
      console.log('Expired sessions cleaned up successfully.');
   } catch (error) {
      console.error('Error cleaning up expired sessions:', error);
   }
};

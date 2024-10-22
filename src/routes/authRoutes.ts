import express from 'express';
import {
   register,
   login,
   verifyEmail,
   logout,
   forgotPassword,
   resetPassword,
} from '../controllers/authController';
import { getDashboard } from '../controllers/userController';
import { protect } from '../middleware/authMiddleware';

const router = express.Router();

// Public routes
router.post('/register', register);
router.get('/verify-email', verifyEmail);

router.post('/login', login);

router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);

// Protected route for user profile
router.get('/logout', protect, logout);
router.get('/dashboard', protect, getDashboard);

export default router;

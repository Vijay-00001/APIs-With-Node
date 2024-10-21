import express from 'express';
import { register, login, verifyEmail } from '../controllers/authController';
import { getProfile } from '../controllers/userController';
import { protect } from '../middleware/authMiddleware';

const router = express.Router();

// Public routes
router.post('/register', register);
router.get('/verify-email', verifyEmail);

router.post('/login', login);

// Protected route for user profile
router.get('/profile', protect, getProfile);

export default router;

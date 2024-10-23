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
import { validateBodyRequest } from '../middleware/validateBodyRequest';
import {
   forgotPasswordValidation,
   loginValidation,
   registerValidation,
   resetPasswordValidation,
   verifyEmailValidation,
} from '../validator/authValidator';

const router = express.Router();

// Public routes
router.post('/register', registerValidation, validateBodyRequest, register);
router.post(
   '/verify-email',
   verifyEmailValidation,
   validateBodyRequest,
   verifyEmail
);
router.post('/login', loginValidation, validateBodyRequest, login);
router.post(
   '/forgot-password',
   forgotPasswordValidation,
   validateBodyRequest,
   forgotPassword
);
router.post(
   '/reset-password',
   resetPasswordValidation,
   validateBodyRequest,
   resetPassword
);

// Protected route for user profile
router.get('/logout', protect, logout);
router.get('/dashboard', protect, getDashboard);

export default router;

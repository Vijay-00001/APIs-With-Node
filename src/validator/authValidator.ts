import { body, query } from 'express-validator';

// Add validation middleware for registration
export const registerValidation = [
   body('name').not().isEmpty().withMessage('Name is required'),
   body('email').isEmail().withMessage('Invalid email address'),
   body('password')
      .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{6,}$/)
      .withMessage(
         'Password must be at least 6 characters long and include a number, a lowercase letter, a capital letter and a special symbol'
      ),
];

// Add validation middleware for email verification
export const verifyEmailValidation = [
   query('token').not().isEmpty().withMessage('Token is required'),
   body('verificationCode')
      .isLength({ min: 6, max: 6 })
      .not()
      .isEmpty()
      .withMessage('Verification code is required'),
];

// Add validation middleware for login
export const loginValidation = [
   body('email').isEmail().withMessage('Invalid email address'),
   body('password')
      .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{6,}$/)
      .withMessage(
         'Password must be at least 6 characters long and include a number, a lowercase letter, a capital letter and a special symbol'
      ),
];

// Add validation middleware for forgot password
export const forgotPasswordValidation = [
   body('email').isEmail().withMessage('Invalid email address'),
];

// Add validation middleware for reset password
export const resetPasswordValidation = [
   query('token').not().isEmpty().withMessage('Token is required'),
   body('newPassword')
      .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{6,}$/)
      .withMessage(
         'Password must be at least 6 characters long and include a number, a lowercase letter, a capital letter and a special symbol'
      ),
   body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.newPassword) {
         throw new Error('Passwords do not match');
      }
      return true;
   }),
];

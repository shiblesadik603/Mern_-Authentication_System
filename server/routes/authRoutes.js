import express from 'express';
import { register, login, logout, sendVerifyOTP, verifyEmail, isAuthenticated, sendResetOtp, resetPassword } from '../controllers/authController.js';
import userAuth from '../middleware/userAuth.js';
import rateLimit from 'express-rate-limit';

// max 10 attempts per 15 minutes per IP, so a 6-digit OTP or a password
// can't be brute forced
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: { success: false, message: 'Too many attempts, please try again later' },
});

const authRouter = express.Router();

authRouter.post('/register', register);
authRouter.post('/login', authLimiter, login);
authRouter.post('/logout', logout);
authRouter.post('/send-verify-otp', userAuth,sendVerifyOTP);
authRouter.post('/verify-account',authLimiter,userAuth,verifyEmail);
authRouter.get('/is-auth',userAuth,isAuthenticated);
authRouter.post('/send-reset-otp',authLimiter,sendResetOtp);
authRouter.post('/reset-password',authLimiter,resetPassword);


export default authRouter;
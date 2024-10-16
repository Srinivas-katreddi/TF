import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './ForgotPassword.css'; // Add CSS styling for the forgot password page

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [stage, setStage] = useState('requestOtp'); // 'requestOtp', 'verifyOtp', or 'resetPassword'
  const [error, setError] = useState('');
  const navigate = useNavigate();

  // Handle OTP Request
  const handleRequestOtp = async (e) => {
    e.preventDefault();
    setError(''); // Clear previous errors

    try {
      const response = await fetch('http://localhost:5000/send-otp', {
        method: 'POST',
        body: JSON.stringify({ email }),
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const result = await response.text();
      if (response.ok && result === 'OTP sent to your email') {
        setStage('verifyOtp'); // Move to OTP verification stage
      } else {
        setError(result || 'Failed to send OTP');
      }
    } catch (err) {
      console.error('Error sending OTP:', err);
      setError('Failed to send OTP');
    }
  };

  // Handle OTP Verification
  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    setError(''); // Clear previous errors

    try {
      const response = await fetch('http://localhost:5000/verify-otp', {
        method: 'POST',
        body: JSON.stringify({ email, otp }),
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const result = await response.text();
      if (result === 'OTP verified') {
        setStage('resetPassword'); // Move to password reset stage
      } else {
        setError(result || 'Invalid OTP');
      }
    } catch (err) {
      console.error('Error verifying OTP:', err);
      setError('Failed to verify OTP');
    }
  };

  // Handle Password Reset
  const handleResetPassword = async (e) => {
    e.preventDefault();
    setError(''); // Clear previous errors

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    try {
      const response = await fetch('http://localhost:5000/reset-password', {
        method: 'POST',
        body: JSON.stringify({ email, otp, newPassword }),
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const result = await response.text();
      if (result === 'Password has been reset') {
        alert('Password reset successful!');
        navigate('/login'); // Redirect to login page after successful password reset
      } else {
        setError(result || 'Failed to reset password');
      }
    } catch (err) {
      console.error('Error resetting password:', err);
      setError('Failed to reset password');
    }
  };

  // Handle Cancel Action to go back to login
  const handleCancel = () => {
    navigate('/login');
  };

  return (
    <div className="forgot-password-wrapper">
      <div className="forgot-password-container">
        <h1>Forgot Password</h1>
        {error && <p className="error-message">{error}</p>}

        {stage === 'requestOtp' ? (
          <form onSubmit={handleRequestOtp}>
            <input
              type="email"
              placeholder="Enter your email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            <button type="submit">Send OTP</button>
          </form>
        ) : stage === 'verifyOtp' ? (
          <form onSubmit={handleVerifyOtp}>
            <input
              type="text"
              placeholder="Enter OTP"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              required
            />
            <div className="button-container">
              <button type="submit">Verify OTP</button>
              <button onClick={handleCancel} className="cancel-button">Cancel</button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleResetPassword}>
            <input
              type="password"
              placeholder="Enter new password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
            <input
              type="password"
              placeholder="Confirm new password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
            <div className="button-container">
              <button type="submit">Reset Password</button>
              <button onClick={handleCancel} className="cancel-button">Cancel</button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

export default ForgotPassword;

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './index.css';
// Adjust the import path for Home

const Login = ({ onLogin }) => {
  const [isRightPanelActive, setIsRightPanelActive] = useState(false);
  const [loginError, setLoginError] = useState('');
  const navigate = useNavigate();

  const handleSignUpClick = () => {
    setIsRightPanelActive(true);
    navigate('/Login');
  };

  const handleSignInClick = () => {
    setIsRightPanelActive(false);
  };

  const handleRegisterSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);

    const response = await fetch('http://localhost:5000/register', {
      method: 'POST',
      body: JSON.stringify(data),
      headers: {
        'Content-Type': 'application/json',
      },
    });

    const result = await response.text();
    if (result.includes('User registered...')) {
      window.location.href = '/Login';
    } else {
      alert(result);
    }
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);

    const response = await fetch('http://localhost:5000/login', {
      method: 'POST',
      body: new URLSearchParams(formData),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const data = await response.json();
    if (data.message === 'Login successful') {
      localStorage.setItem('token', data.token);
      onLogin(data.token);
      navigate('/');  // Redirect to Home page after login
    } else {
      setLoginError("Incorrect email or password. Try again.");
    }
  };

  return (
    <div className="main-container"> {/* New container added */}
      <div className={`containerLc ${isRightPanelActive ? "right-panel-active" : ""}`} id="containerLd">
        <div className="form-container sign-in-container">
          <form id="loginform" onSubmit={handleLoginSubmit}>
            <h1>Login</h1>
            <input type="email" name="email" placeholder="Email" required />
            <input type="password" name="pass" placeholder="Password" required />
            <a href="/forgot-password">Forgot your password?</a>
            <button type="submit">Login</button>
            {loginError && <p style={{ color: 'red' }}>{loginError}</p>}
          </form>
        </div>

        <div className="form-container sign-up-container">
          <form id="registerform" onSubmit={handleRegisterSubmit}>
            <h1>Create Account</h1>
            <input type="text" name="name" placeholder="Name" required />
            <input type="email" name="email" placeholder="Email" required />
            <input type="tel" name="tel" placeholder="Phone" required />
            <input type="password" name="password" placeholder="Password" required />
            <input type="password" name="confirmPass" placeholder="Re-enter Password" required />
            <button type="submit">Sign Up</button>
          </form>
        </div>

        <div className="overlay-container">
          <div className="overlay">
            <div className="overlay-panel overlay-left">
              <h1>We Keep Connected!</h1>
              <p>To keep connected with us, please login with your personal info</p>
              <button className="ghost" id="signIn" onClick={handleSignInClick}>Login</button>
            </div>
            <div className="overlay-panel overlay-right">
              <h1>Hello, Traveler!</h1>
              <p>Enter your personal details and start your journey with us</p>
              <button className="ghost" id="signUp" onClick={handleSignUpClick}>Register</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;

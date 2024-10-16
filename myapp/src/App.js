import React, { useState, useEffect } from 'react';
import Header from './component/Header';
import Home from './component/Home';
import PlanMyBudget from './component/PlanMyBudget';
import ServicesSection from './component/ServiceSection';
import Profile from './component/Profile';
import AboutSection from './component/AboutSection';
import ForgotPassword from './component/Login/ForgotPassword';
import Search from './component/Search/Search';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './component/Login'; // Corrected path assuming it's in the components folder
import './App.css'; // General app styles

const App = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Check if the user is authenticated by looking at the token
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      setIsAuthenticated(true);
    }
  }, []);

  // Toggle menu visibility
  const handleMenuToggle = () => {
    setIsMenuOpen(!isMenuOpen);
  };

  const handleLogin = (token) => {
    localStorage.setItem('token', token);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setIsAuthenticated(false);
    window.location.href = '/login'; // Redirect to login on logout
  };

  // Private route component
  const PrivateRoute = ({ element }) => {
    return isAuthenticated ? (
      <>
        <Header isMenuOpen={isMenuOpen} onMenuToggle={handleMenuToggle} onLogout={handleLogout} /> 
        {element}
      </>
    ) : (
      <Navigate to="/login" />
    );
  };

  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login onLogin={handleLogin} />} />
        <Route path="/" element={<PrivateRoute element={<Home />} />} />
        <Route path="/planmybudget" element={<PrivateRoute element={<PlanMyBudget />} />} />
        <Route path="/services" element={<PrivateRoute element={<ServicesSection />} />} />
        <Route path="/profile" element={<PrivateRoute element={<Profile />} />} />
        <Route path="/Search" element={<Search />} />
        <Route path="/about" element={<PrivateRoute element={<AboutSection />} />} />
        { <Route path="/forgot-password" element={<ForgotPassword />} /> }
      </Routes>
    </Router>
  );
};

export default App;

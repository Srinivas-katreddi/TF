import React, { useState } from 'react';
import './index.css';
import { Link } from 'react-router-dom';

const Header = () => {
    const [isMenuOpen, setIsMenuOpen] = useState(false);
    const [isChecked, setIsChecked] = useState(false);
    // Toggle menu visibility
    const handleMenuToggle = () => {
      setIsMenuOpen(!isMenuOpen);
      setIsChecked(!isChecked);
    };
   

    // const handleToggle = () => {
      
    // };
  
  
    return (
      <header className="header-nav">
        <div className="container-nav">
          <div className="logo">
            {/* <h1>TBM</h1> */}
            <img className='logo-img' src="https://res.cloudinary.com/drzlum1yv/image/upload/v1728962960/Screenshot_2024-10-10_204829_kgghl1.png " alt="logo" />
          </div>
          <nav className={`nav ${isMenuOpen ? 'active' : ''}`}>
            <ul className={`nav__list ${isMenuOpen ? 'show' : ''}`}>
              <li className="nav__item"><Link to ="/" >Home</Link></li>
              <li className="nav__item"><Link to="/planmybudget" >Plan My Budget</Link></li>
              <li className="nav__item"><Link to="/services" >Services</Link></li>
              <li className="nav__item"><Link to="/profile" >Profile</Link></li>
              <li className="nav__item"><Link to="/about" >About Us</Link></li>
            </ul>
          </nav>
          <div className="menu-toggle" aria-label="Toggle navigation">
            {/* <span className="menu-icon"></span>
            <span className="menu-icon"></span>
            <span className="menu-icon"></span> */}
            <label className="hamburger">
      <input
        type="checkbox"
        checked={isChecked}
        onClick={handleMenuToggle} 
        aria-label="Toggle menu"
      />
      <svg viewBox="0 0 32 32">
        <path
          className={`line line-top-bottom ${isChecked ? 'active' : ''}`}
          d="M27 10 13 10C10.8 10 9 8.2 9 6 9 3.5 10.8 2 13 2 15.2 2 17 3.8 17 6L17 26C17 28.2 18.8 30 21 30 23.2 30 25 28.2 25 26 25 23.8 23.2 22 21 22L7 22"
        />
        <path
          className={`line ${isChecked ? 'active' : ''}`}
          d="M7 16 27 16"
        />
      </svg>
    </label>
          </div>
        </div>
      </header>
    );
  };
  

export default Header;
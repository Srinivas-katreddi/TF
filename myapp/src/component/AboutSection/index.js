// AboutSection.js
import React from 'react';
import Team from './Team.js';
import './index.css'

function AboutSection() {
  return (
    <section className="about-section">
      <div className="container-about">
        <h1>About Us</h1>
        <p><b>Welcome to our company. We are dedicated to providing the best services to our customers. Our team of professionals is here to help you achieve your goals.</b></p>
        <h2>Our Mission</h2>
        <p><b>Our mission is to minimize the budget for traveling that brings value to our customers. We strive for excellence in every project we undertake.</b></p>
        <h2>Our Team</h2>
        <Team />
      </div>
    </section>
  );
}

export default AboutSection;
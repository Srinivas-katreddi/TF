import React from 'react';
import './index.css';

function ServicesSection() {
  return (
    <section className="services-section">
      <div className="containers1">
        <h1>Our Services</h1>
        <div className="service">
          <h2>Personalized Budget Planning</h2>
          <p><b>We help you create a customized budget plan for your travels, ensuring you can enjoy your trip without financial stress.</b></p>
        </div>
        <div className="service">
          <h2>Expense Tracking</h2>
          <p><b>Track all your travel expenses in real-time with our easy-to-use tracking tools. Stay on top of your budget wherever you are.</b></p>
        </div>
        <div className="service">
          <h2>Cost-saving Tips</h2>
          <p><b>Receive expert advice and tips on how to save money on flights, accommodations, and other travel-related expenses.</b></p>
        </div>
        <div className="service">
          <h2>Financial Consultation</h2>
          <p><b>Get one-on-one financial consultation with our experts to make the most out of your travel budget.</b></p>
        </div>
      </div>
    </section>
  );
}

export default ServicesSection;
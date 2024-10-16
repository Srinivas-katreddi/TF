import React, { useState, useEffect } from 'react';
import './index.css';

const Profile = () => {
    const [user, setUser] = useState({});
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchUserData = async () => {
            try {
              const token = localStorage.getItem('token');
              
              if (!token) {
                throw new Error('No token found');
              }
          
              const response = await fetch('http://localhost:5000/profile', {
                method: 'GET',
                headers: {
                  'Authorization': `Bearer ${token}`,
                  'Content-Type': 'application/json'
                },
              });
          
              if (!response.ok) {
                throw new Error('Failed to fetch user data');
              }
          
              const data = await response.json();
              setUser(data);
            } catch (err) {
              setError(err.message);
            } finally {
              setLoading(false);
            }
          };
          

        fetchUserData();
    }, []);

    const handleSignOut = () => {
        // Clear token on sign out
        localStorage.removeItem('token');
        window.location.href = '/login'; // Redirect to login page
    };

    if (loading) {
        return <div>Loading...</div>;
    }

    if (error) {
        return <div>Error: {error}</div>;
    }

    return (
        <div>
            <section className="profile-section">
                <div className="container-profile">
                    <div className="profile-header">
                        <img
                            src="https://static.vecteezy.com/system/resources/previews/007/522/850/original/business-man-icon-for-your-web-profile-free-vector.jpg"
                            alt="Profile"
                            className="profile-pic"
                        />
                        <h1>{user.name || "John Doe"}</h1>
                        <button className="sign-out" onClick={handleSignOut}>
                            Sign Out
                        </button>
                    </div>
                    <div className="profile-details">
                        <h2>About Me</h2>
                        <p>
                            <b>
                                Hi, I'm {user.name || "John Doe"}, a travel enthusiast and budget management expert.
                                I love sharing my experiences and tips with fellow travelers.
                            </b>
                        </p>
                        <h2>Contact Information</h2>
                        <p><b>Email: {user.email || "john.doe@example.com"}</b></p>
                        <p><b>Phone: {user.phone || "+123-456-7890"}</b></p>
                    </div>
                </div>
            </section>
        </div>
    );
}

export default Profile;

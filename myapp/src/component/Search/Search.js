import React from 'react';
import { Link } from 'react-router-dom';
import './Search.css'; // Ensure you include necessary CSS

const Search = () => {
  return (
    <div className="search-page">
      <div className="under-construction-container">
        <h2 className="text-center mb-4">Search Results</h2>

        {/* Under Construction Image */}
        <img
          src="https://cdn.dribbble.com/users/299116/screenshots/11076555/media/72493ce172613de72e442e435209b1aa.jpg?resize=1000x750&vertical=center"
          alt="Under Construction"
          className="under-construction-image"
        />
        <p className="text-center-mt-3"><b>This page is under construction. Please check back later!</b></p>

        {/* Button to navigate back to Plan My Budget page */}
        <div className="text-center mt-4">
          <Link to="/PlanMyBudget">
            <button className="btn btn-primary">Go Back to Plan My Budget</button>
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Search;

import './index.css';
import 'bootstrap/dist/css/bootstrap.min.css';
import { useState, useEffect } from 'react';
import Data from './Data.json'; // Path to your JSON file
import { useNavigate } from 'react-router-dom'; 

const PlanMyBudget = () => {
  const [sourceState, setSourceState] = useState('');
  const [sourceCity, setSourceCity] = useState('');
  const [filteredSourceCities, setFilteredSourceCities] = useState([]);

  const [destinationState, setDestinationState] = useState('');
  const [destinationCity, setDestinationCity] = useState('');
  const [filteredDestinationCities, setFilteredDestinationCities] = useState([]);

  const [budget, setBudget] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  const [states, setStates] = useState([]);
  const [cities, setCities] = useState([]);

  const navigate = useNavigate();

  // Function to extract states and cities from the JSON file
  useEffect(() => {
    const employees = Data.Employees.Employee; // Access the Employee array
    const uniqueStates = new Set();
    const citiesData = [];

    // Debugging: Log the entire employee data to the console
    console.log('Parsed JSON Data:', employees);

    employees.forEach((row) => {
      const state = row.State ? row.State.trim() : '';
      const city = row['City \r'] ? row['City \r'].trim() : ''; // Handle the trailing \r

      // Check for valid state and city values
      if (state) {
        uniqueStates.add(state);
      }

      if (city && state) {
        citiesData.push({
          city: city,
          state: state,
        });
      }
    });

    setStates(Array.from(uniqueStates));
    setCities(citiesData);

    // Log unique states and cities for debugging
    console.log('Unique States:', Array.from(uniqueStates));
    console.log('Cities Data:', citiesData);
  }, []);

  // Update cities dropdown for source when a state is selected
  useEffect(() => {
    if (sourceState) {
      const filtered = cities.filter((city) => city.state.toLowerCase() === sourceState.toLowerCase());
      setFilteredSourceCities(filtered);
      console.log('Filtered Source Cities:', filtered); // Debugging
    } else {
      setFilteredSourceCities([]);
    }
  }, [sourceState, cities]);

  // Update cities dropdown for destination when a state is selected
  useEffect(() => {
    if (destinationState) {
      const filtered = cities.filter((city) => city.state.toLowerCase() === destinationState.toLowerCase());
      setFilteredDestinationCities(filtered);
      console.log('Filtered Destination Cities:', filtered); // Debugging
    } else {
      setFilteredDestinationCities([]);
    }
  }, [destinationState, cities]);

  // Function to handle the form submission
  const handleSearch = () => {
    if (!sourceState || !sourceCity || !destinationState || !destinationCity || !budget) {
      setErrorMessage('Please fill all the fields');
    } else {
      setErrorMessage('');
      navigate('/Search'); // Navigate to the Search page if all fields are filled
    }
  };

  return (
    <div className='main-division'>
      <div className='main-cont-div mt-5'>
        <div id="containerpmb">
          <div className="d-flex flex-column">
            <h2 className='mb-2 main-head'>Plan My Trip Within My Budget</h2>

            {/* Source Dropdown */}
            <div className="source-cont mt-3">
              <h5>Source</h5>
              <div className="d-flex">
                {/* Source State Dropdown */}
                <select
                  className="form-control m-2"
                  value={sourceState}
                  onChange={(e) => setSourceState(e.target.value)}
                >
                  <option value="">--State--</option>
                  {states.map((state, index) => (
                    <option key={index} value={state}>
                      {state}
                    </option>
                  ))}
                </select>

                {/* Source City Dropdown */}
                <select
                  className="form-control m-2"
                  value={sourceCity}
                  onChange={(e) => setSourceCity(e.target.value)}
                  disabled={!sourceState}
                >
                  <option value="">--City--</option>
                  {filteredSourceCities.map((city, index) => (
                    <option key={index} value={city.city}>
                      {city.city}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Destination Dropdown */}
            <div className="dest-cont mt-3">
              <h5>Destination</h5>
              <div className="d-flex">
                {/* Destination State Dropdown */}
                <select
                  className="form-control m-2"
                  value={destinationState}
                  onChange={(e) => setDestinationState(e.target.value)}
                >
                  <option value="">--State--</option>
                  {states.map((state, index) => (
                    <option key={index} value={state}>
                      {state}
                    </option>
                  ))}
                </select>

                {/* Destination City Dropdown */}
                <select
                  className="form-control m-2"
                  value={destinationCity}
                  onChange={(e) => setDestinationCity(e.target.value)}
                  disabled={!destinationState}
                >
                  <option value="">--City--</option>
                  {filteredDestinationCities.map((city, index) => (
                    <option key={index} value={city.city}>
                      {city.city}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Budget Dropdown */}
            <div className='dest-cont mt-3'>
              <h5>Budget</h5>
              <div className="d-flex">
                <select
                  className="form-control m-2"
                  value={budget}
                  onChange={(e) => setBudget(e.target.value)}
                >
                  <option value="">--Budget--</option>
                  <option value="1">Low Budget</option>
                  <option value="2">Medium Budget</option>
                  <option value="3">High Budget</option>
                </select>
              </div>
            </div>

            {/* Error Message */}
            {errorMessage && <p className="text-danger">{errorMessage}</p>}

            {/* Search Button */}
            <button className='search-btn mt-3' onClick={handleSearch}>
              Search
            </button>
          </div>

          {/* Image Grid */}
          <div className="grid">
            <img id="item1" src="https://res.cloudinary.com/drzlum1yv/image/upload/v1723369875/jumbo-jet-flying-sky_ihcwgv.jpg" alt="Item 1" text="Travel By Aeroplane" />
            <img id="item2" src="https://res.cloudinary.com/drzlum1yv/image/upload/v1723370659/budget_ejq0gn.jpg" alt="Item 2" text="Travel By Bus"/>
            <img id="item3" src="https://res.cloudinary.com/drzlum1yv/image/upload/v1728962960/Screenshot_2024-10-10_204829_kgghl1.png " alt="Item 3" text="Travel By Train"/>
            <img id="item4" src="https://res.cloudinary.com/drzlum1yv/image/upload/v1723370689/train_odrx45.jpg" alt="Item 4" text="Budget Friendly"/>
            <img id="item5" src="https://res.cloudinary.com/drzlum1yv/image/upload/v1723370701/bus_uobus9.jpg" alt="Item 5" text="Travel With In Budget"/>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PlanMyBudget;

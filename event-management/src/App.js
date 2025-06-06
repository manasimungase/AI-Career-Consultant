import React, { useState, useEffect } from 'react';
import axios from 'axios';

const App = () => {
    const [events, setEvents] = useState([]);
    const [title, setTitle] = useState('');
    const [description, setDescription] = useState('');
    const [userId, setUserId] = useState('');

    // Fetch all events
    useEffect(() => {
        axios.get('http://localhost:5000/api/events')
            .then(response => setEvents(response.data))
            .catch(error => console.error(error));
    }, []);

    // Create Event
    const createEvent = () => {
        const event = { title, description };
        axios.post('http://localhost:5000/api/events', event)
            .then(response => {
                setEvents([...events, response.data]);
                setTitle('');
                setDescription('');
            })
            .catch(error => console.error(error));
    };

    // Register for Event
    const registerForEvent = (eventId) => {
        axios.post(`http://localhost:5000/api/events/${eventId}/register`, { userId })
            .then(response => alert(response.data.message))
            .catch(error => console.error(error));
    };

    // Submit Feedback
    const submitFeedback = (eventId) => {
        const feedback = { userId, rating: 5, comments: 'Great event!' };
        axios.post(`http://localhost:5000/api/events/${eventId}/feedback`, feedback)
            .then(response => alert(response.data.message))
            .catch(error => console.error(error));
    };

    return (
        <div style={{ padding: '20px' }}>
            <h1>Event Management</h1>

            {/* Create Event Form */}
            <div>
                <h2>Create Event</h2>
                <input
                    type="text"
                    placeholder="Title"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                />
                <input
                    type="text"
                    placeholder="Description"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                />
                <button onClick={createEvent}>Create Event</button>
            </div>

            {/* User ID Input */}
            <div>
                <h2>User ID</h2>
                <input
                    type="text"
                    placeholder="Enter User ID"
                    value={userId}
                    onChange={(e) => setUserId(e.target.value)}
                />
            </div>

            {/* Event List */}
            <div>
                <h2>Upcoming Events</h2>
                {events.map(event => (
                    <div key={event.title} style={{ border: '1px solid #ccc', padding: '10px', margin: '10px 0' }}>
                        <h3>{event.title}</h3>
                        <p>{event.description}</p>
                        <button onClick={() => registerForEvent(event.title)}>Register</button>
                        <button onClick={() => submitFeedback(event.title)}>Submit Feedback</button>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default App;
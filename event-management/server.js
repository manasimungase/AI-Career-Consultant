const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

let events = [];
let registrations = [];
let feedbacks = [];

// Create Event
app.post('/api/events', (req, res) => {
    const event = req.body;
    events.push(event);
    res.status(201).json(event);
});

// Get All Events
app.get('/api/events', (req, res) => {
    res.json(events);
});

// Register for Event
app.post('/api/events/:eventId/register', (req, res) => {
    const { eventId } = req.params;
    const { userId } = req.body;

    const registration = { eventId, userId };
    registrations.push(registration);
    res.json({ message: 'Registration successful', registration });
});

// Submit Feedback
app.post('/api/events/:eventId/feedback', (req, res) => {
    const { eventId } = req.params;
    const { userId, rating, comments } = req.body;

    const feedback = { eventId, userId, rating, comments };
    feedbacks.push(feedback);
    res.json({ message: 'Feedback submitted', feedback });
});

// Start Server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
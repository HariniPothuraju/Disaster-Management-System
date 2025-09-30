// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');

const app = express();
const server = http.createServer(app);

// WebSocket Server for real-time features
const wss = new WebSocket.Server({ server });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Environment variables (use process.env in production)
const PORT = process.env.PORT || 5001;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/rescueconnect';
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key_here';

// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.log('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String },
  location: {
    latitude: { type: Number },
    longitude: { type: Number },
    lastUpdated: { type: Date }
  },
  healthInfo: {
    bloodType: { type: String },
    allergies: { type: String },
    medications: { type: String },
    conditions: { type: String },
    emergencyContact: { type: String }
  },
  isVolunteer: { type: Boolean, default: false },
  volunteerInfo: {
    skills: [{ type: String }],
    certifications: [{ type: String }],
    availability: { type: Boolean, default: false }
  },
  createdAt: { type: Date, default: Date.now }
});

// SOS Alert Schema
const alertSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  location: {
    latitude: { type: Number, required: true },
    longitude: { type: Number, required: true }
  },
  type: { type: String, enum: ['earthquake', 'flood', 'fire', 'medical', 'other'], required: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
  description: { type: String },
  status: { type: String, enum: ['active', 'resolved', 'cancelled'], default: 'active' },
  responders: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  resolvedAt: { type: Date }
});

// Climate Data Schema
const climateSchema = new mongoose.Schema({
  temperature: { type: Number, required: true },
  humidity: { type: Number, required: true },
  pressure: { type: Number, required: true },
  windSpeed: { type: Number, required: true },
  location: {
    latitude: { type: Number, required: true },
    longitude: { type: Number, required: true }
  },
  riskLevel: { type: String, enum: ['low', 'medium', 'high'], default: 'low' },
  timestamp: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Alert = mongoose.model('Alert', alertSchema);
const ClimateData = mongoose.model('ClimateData', climateSchema);

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// WebSocket connection handling
wss.on('connection', (ws) => {
  console.log('Client connected');
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'location') {
        // Update user location in database
        User.findByIdAndUpdate(data.userId, {
          location: {
            latitude: data.latitude,
            longitude: data.longitude,
            lastUpdated: new Date()
          }
        }).exec();
        
        // Broadcast to other clients (for real-time tracking)
        wss.clients.forEach(client => {
          if (client !== ws && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'location_update',
              userId: data.userId,
              latitude: data.latitude,
              longitude: data.longitude
            }));
          }
        });
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  });
  
  ws.on('close', () => {
    console.log('Client disconnected');
  });
});

// Routes

// User registration
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword,
      phone
    });
    
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        isVolunteer: user.isVolunteer
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update user profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone, healthInfo } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { name, phone, healthInfo },
      { new: true }
    ).select('-password');
    
    res.json({
      message: 'Profile updated successfully',
      user: updatedUser
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Create SOS alert
app.post('/api/alerts', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude, type, severity, description } = req.body;
    
    const alert = new Alert({
      userId: req.user.userId,
      location: { latitude, longitude },
      type,
      severity,
      description
    });
    
    await alert.save();
    
    // Populate user info for response
    await alert.populate('userId', 'name email phone');
    
    // Broadcast alert to all connected clients (for real-time notifications)
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          type: 'new_alert',
          alert
        }));
      }
    });
    
    res.status(201).json({
      message: 'Alert created successfully',
      alert
    });
  } catch (error) {
    console.error('Alert creation error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get all active alerts
app.get('/api/alerts', authenticateToken, async (req, res) => {
  try {
    const alerts = await Alert.find({ status: 'active' })
      .populate('userId', 'name phone')
      .sort({ createdAt: -1 });
    
    res.json(alerts);
  } catch (error) {
    console.error('Alerts fetch error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get user's alerts
app.get('/api/my-alerts', authenticateToken, async (req, res) => {
  try {
    const alerts = await Alert.find({ userId: req.user.userId })
      .sort({ createdAt: -1 });
    
    res.json(alerts);
  } catch (error) {
    console.error('User alerts fetch error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update alert status
app.put('/api/alerts/:id', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    
    const updateData = { status };
    if (status === 'resolved') {
      updateData.resolvedAt = new Date();
    }
    
    const alert = await Alert.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );
    
    if (!alert) {
      return res.status(404).json({ message: 'Alert not found' });
    }
    
    res.json({
      message: 'Alert updated successfully',
      alert
    });
  } catch (error) {
    console.error('Alert update error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Respond to alert (for volunteers)
app.post('/api/alerts/:id/respond', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user.isVolunteer) {
      return res.status(403).json({ message: 'Only volunteers can respond to alerts' });
    }
    
    const alert = await Alert.findById(req.params.id);
    if (!alert) {
      return res.status(404).json({ message: 'Alert not found' });
    }
    
    // Check if user is already a responder
    if (alert.responders.includes(req.user.userId)) {
      return res.status(400).json({ message: 'You are already responding to this alert' });
    }
    
    alert.responders.push(req.user.userId);
    await alert.save();
    
    res.json({
      message: 'You are now responding to this alert',
      alert
    });
  } catch (error) {
    console.error('Alert response error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get climate data
app.get('/api/climate-data', async (req, res) => {
  try {
    // In a real app, you would fetch this from a weather API
    // For demo purposes, we'll generate random data
    const climateData = {
      temperature: Math.floor(Math.random() * 30) + 10, // 10-40°C
      humidity: Math.floor(Math.random() * 50) + 30, // 30-80%
      pressure: Math.floor(Math.random() * 50) + 1000, // 1000-1050 hPa
      windSpeed: Math.floor(Math.random() * 50) + 5, // 5-55 km/h
      riskLevel: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)],
      timestamp: new Date()
    };
    
    res.json(climateData);
  } catch (error) {
    console.error('Climate data fetch error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update user location
app.post('/api/location', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude } = req.body;
    
    await User.findByIdAndUpdate(req.user.userId, {
      location: {
        latitude,
        longitude,
        lastUpdated: new Date()
      }
    });
    
    res.json({ message: 'Location updated successfully' });
  } catch (error) {
    console.error('Location update error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get nearby volunteers
app.get('/api/nearby-volunteers', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user.location) {
      return res.status(400).json({ message: 'User location not available' });
    }
    
    // In a real app, you would use geospatial queries
    // For demo, we'll just return some mock data
    const volunteers = await User.find({
      isVolunteer: true,
      _id: { $ne: req.user.userId }
    }).select('name phone location');
    
    res.json(volunteers);
  } catch (error) {
    console.error('Nearby volunteers fetch error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Become a volunteer
app.post('/api/become-volunteer', authenticateToken, async (req, res) => {
  try {
    const { skills, certifications } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      {
        isVolunteer: true,
        volunteerInfo: {
          skills,
          certifications,
          availability: true
        }
      },
      { new: true }
    );
    
    res.json({
      message: 'You are now a volunteer',
      user
    });
  } catch (error) {
    console.error('Volunteer registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get all volunteers
app.get('/api/volunteers', authenticateToken, async (req, res) => {
  try {
    const volunteers = await User.find({ isVolunteer: true })
      .select('name email phone volunteerInfo location');
    
    res.json(volunteers);
  } catch (error) {
    console.error('Volunteers fetch error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'client', 'build')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client', 'build', 'index.html'));
  });
}

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
// Sample Express.js API structure
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// API Routes
app.post('/api/auth/login', (req, res) => {
  // Validate credentials, generate JWT token
});

app.post('/api/auth/register', (req, res) => {
  // Create new user, generate JWT token
});

app.get('/api/climate/current', (req, res) => {
  // Return current climate data
});

app.get('/api/impact/stats', (req, res) => {
  // Return impact statistics
});

app.post('/api/emergency/sos', authenticateToken, (req, res) => {
  // Process SOS emergency alert
});

app.get('/api/user/profile', authenticateToken, (req, res) => {
  // Return user profile data
});

app.post('/api/user/settings', authenticateToken, (req, res) => {
  // Save user settings
});

app.post('/api/risk/prediction', authenticateToken, (req, res) => {
  // Calculate and return risk prediction
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

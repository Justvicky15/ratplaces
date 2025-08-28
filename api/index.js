const fs = require('fs');
const path = require('path');

// File paths for data storage
const PROGRAMS_FILE = path.join(__dirname, 'programs.json');
const LOGINS_FILE = path.join(__dirname, 'logins.json');

// Utility function to read JSON files
function readJsonFile(filePath, defaultValue = []) {
  try {
    if (fs.existsSync(filePath)) {
      const data = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(data);
    }
  } catch (error) {
    console.error(`Error reading ${filePath}:`, error);
  }
  return defaultValue;
}

// Utility function to write JSON files
function writeJsonFile(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (error) {
    console.error(`Error writing ${filePath}:`, error);
    return false;
  }
}

// Utility function to validate authentication token
function validateAuthToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  const token = authHeader.substring(7);
  
  // For demo purposes, any valid JWT-like token is accepted
  // In production, implement proper JWT validation
  if (token && token.length > 10) {
    return { valid: true, username: 'admin' };
  }
  
  return null;
}

// Generate simple token
function generateToken(username) {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2);
  return `${username}_${timestamp}_${random}`;
}

// CORS headers for cross-origin requests
function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

// Main serverless handler
module.exports = async (req, res) => {
  // Set CORS headers
  setCorsHeaders(res);
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  try {
    const { method, url } = req;
    const urlPath = url.split('?')[0]; // Remove query parameters
    const segments = urlPath.split('/').filter(Boolean);
    
    // Remove 'api' from segments if present (for routing compatibility)
    if (segments[0] === 'api') {
      segments.shift();
    }

    console.log(`API Request: ${method} ${urlPath}`, { segments });

    // Routes
    switch (method) {
      case 'GET':
        return await handleGetRequest(req, res, segments);
      case 'POST':
        return await handlePostRequest(req, res, segments);
      case 'PUT':
        return await handlePutRequest(req, res, segments);
      case 'DELETE':
        return await handleDeleteRequest(req, res, segments);
      default:
        res.status(405).json({ 
          success: false, 
          message: `Method ${method} not allowed` 
        });
        return;
    }
  } catch (error) {
    console.error('API Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error',
      error: error.message 
    });
  }
};

// Handle GET requests
async function handleGetRequest(req, res, segments) {
  const endpoint = segments[0] || '';

  switch (endpoint) {
    case 'programs':
      const programs = readJsonFile(PROGRAMS_FILE, []);
      res.status(200).json(programs);
      break;

    case 'announcements':
      // Sample announcements since we don't have a file for this
      const announcements = [
        {
          id: 'ann_1756400000_sample1',
          title: 'Welcome to RatPlace!',
          message: 'Your premier marketplace for security tools and software solutions. Browse our catalog and find what you need!',
          author: 'RatPlace Team',
          createdAt: new Date().toISOString(),
          priority: 'high'
        },
        {
          id: 'ann_1756400100_sample2',
          title: 'New Security Tools Added',
          message: 'Check out the latest additions to our marketplace. High-quality tools from trusted developers.',
          author: 'Admin',
          createdAt: new Date(Date.now() - 3600000).toISOString(),
          priority: 'normal'
        },
        {
          id: 'ann_1756400200_sample3',
          title: 'Quality Guarantee',
          message: 'All tools on RatPlace are tested and verified. Contact sellers directly for support and custom requests.',
          author: 'Quality Team',
          createdAt: new Date(Date.now() - 86400000).toISOString(),
          priority: 'normal'
        }
      ];
      res.status(200).json({
        success: true,
        data: announcements
      });
      break;

    case 'analytics':
      // Simple analytics data
      const analytics = {
        visitors: Math.floor(Math.random() * 500) + 100,
        programs: readJsonFile(PROGRAMS_FILE, []).length,
        announcements: 3,
        users: 3
      };
      res.status(200).json({
        success: true,
        data: analytics
      });
      break;

    case 'health':
      res.status(200).json({
        success: true,
        message: 'API is healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
      break;

    default:
      res.status(404).json({ 
        success: false, 
        message: `Endpoint /${endpoint} not found` 
      });
      break;
  }
}

// Handle POST requests
async function handlePostRequest(req, res, segments) {
  const endpoint = segments[0] || '';

  // Parse request body
  let body = {};
  if (req.body) {
    body = req.body;
  } else {
    // Manual body parsing for raw requests
    let rawBody = '';
    await new Promise((resolve) => {
      req.on('data', chunk => {
        rawBody += chunk.toString();
      });
      req.on('end', () => {
        try {
          body = JSON.parse(rawBody);
        } catch (error) {
          console.error('Error parsing request body:', error);
          body = {};
        }
        resolve();
      });
    });
  }

  switch (endpoint) {
    case 'auth':
      return await handleLogin(req, res, body);

    case 'programs':
      return await handleAddProgram(req, res, body);

    case 'announcements':
      return await handleAddAnnouncement(req, res, body);

    default:
      res.status(404).json({ 
        success: false, 
        message: `POST endpoint /${endpoint} not found` 
      });
      break;
  }
}

// Handle PUT requests
async function handlePutRequest(req, res, segments) {
  const endpoint = segments[0] || '';
  
  switch (endpoint) {
    case 'programs':
      // Validate authentication
      const authResult = validateAuthToken(req.headers.authorization);
      if (!authResult) {
        res.status(401).json({ success: false, message: 'Unauthorized' });
        return;
      }
      
      // Handle program update (placeholder)
      res.status(200).json({
        success: true,
        message: 'Program update endpoint ready for implementation'
      });
      break;

    default:
      res.status(404).json({ 
        success: false, 
        message: `PUT endpoint /${endpoint} not found` 
      });
      break;
  }
}

// Handle DELETE requests
async function handleDeleteRequest(req, res, segments) {
  const endpoint = segments[0] || '';
  
  switch (endpoint) {
    case 'programs':
      // Validate authentication
      const authResult = validateAuthToken(req.headers.authorization);
      if (!authResult) {
        res.status(401).json({ success: false, message: 'Unauthorized' });
        return;
      }
      
      const programId = segments[1];
      if (!programId) {
        res.status(400).json({ success: false, message: 'Program ID required' });
        return;
      }
      
      const programs = readJsonFile(PROGRAMS_FILE, []);
      const filteredPrograms = programs.filter(p => p.id !== programId);
      
      if (programs.length === filteredPrograms.length) {
        res.status(404).json({ success: false, message: 'Program not found' });
        return;
      }
      
      if (writeJsonFile(PROGRAMS_FILE, filteredPrograms)) {
        res.status(200).json({
          success: true,
          message: 'Program deleted successfully'
        });
      } else {
        res.status(500).json({ success: false, message: 'Failed to delete program' });
      }
      break;

    default:
      res.status(404).json({ 
        success: false, 
        message: `DELETE endpoint /${endpoint} not found` 
      });
      break;
  }
}

// Authentication handler
async function handleLogin(req, res, body) {
  const { username, password } = body;

  if (!username || !password) {
    res.status(400).json({
      success: false,
      message: 'Username and password are required'
    });
    return;
  }

  const logins = readJsonFile(LOGINS_FILE, []);
  const user = logins.find(u => u.username === username && u.password === password);

  if (!user) {
    res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
    return;
  }

  const token = generateToken(username);

  res.status(200).json({
    success: true,
    message: 'Login successful',
    token,
    username: user.username,
    avatar: user.avatar || '👤',
    role: user.role || 'admin'
  });
}

// Add program handler
async function handleAddProgram(req, res, body) {
  // Validate authentication for program creation
  const authResult = validateAuthToken(req.headers.authorization);
  if (!authResult) {
    res.status(401).json({ success: false, message: 'Unauthorized' });
    return;
  }

  const { name, category, price, contactUsername, imageUrl, downloadUrl, description, customMessage } = body;

  // Validation
  const errors = [];
  if (!name || name.trim().length === 0) errors.push('Program name is required');
  if (!category) errors.push('Category is required');
  if (price === undefined || price === null) errors.push('Price is required');
  if (!contactUsername || contactUsername.trim().length === 0) errors.push('Contact username is required');
  if (!downloadUrl || downloadUrl.trim().length === 0) errors.push('Download URL is required');
  if (!description || description.trim().length === 0) errors.push('Description is required');

  if (errors.length > 0) {
    res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors
    });
    return;
  }

  // Create new program
  const newProgram = {
    id: `prog_${Date.now()}_${Math.random().toString(36).substring(2)}`,
    name: name.trim(),
    category,
    price: parseFloat(price).toFixed(2),
    contactUsername: contactUsername.trim(),
    imageUrl: imageUrl?.trim() || `https://via.placeholder.com/300x200/000000/FFFFFF?text=${encodeURIComponent(name)}`,
    downloadUrl: downloadUrl.trim(),
    description: description.trim(),
    customMessage: customMessage?.trim() || '',
    createdAt: new Date().toISOString()
  };

  // Add to programs list
  const programs = readJsonFile(PROGRAMS_FILE, []);
  programs.push(newProgram);

  if (writeJsonFile(PROGRAMS_FILE, programs)) {
    res.status(201).json({
      success: true,
      message: 'Program added successfully',
      data: newProgram
    });
  } else {
    res.status(500).json({
      success: false,
      message: 'Failed to save program'
    });
  }
}

// Add announcement handler  
async function handleAddAnnouncement(req, res, body) {
  // Validate authentication
  const authResult = validateAuthToken(req.headers.authorization);
  if (!authResult) {
    res.status(401).json({ success: false, message: 'Unauthorized' });
    return;
  }

  const { title, message, priority, author } = body;

  // Validation
  if (!title || title.trim().length === 0) {
    res.status(400).json({
      success: false,
      message: 'Announcement title is required'
    });
    return;
  }

  if (!message || message.trim().length === 0) {
    res.status(400).json({
      success: false,
      message: 'Announcement message is required'
    });
    return;
  }

  // Create new announcement
  const newAnnouncement = {
    id: `ann_${Date.now()}_${Math.random().toString(36).substring(2)}`,
    title: title.trim(),
    message: message.trim(),
    author: author?.trim() || 'Admin',
    priority: priority || 'normal',
    createdAt: new Date().toISOString()
  };

  // For now, just return success (announcements could be stored in a file if needed)
  res.status(201).json({
    success: true,
    message: 'Announcement created successfully',
    data: newAnnouncement
  });
}

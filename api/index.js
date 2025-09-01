const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');

// Hardcoded admin users
const ADMIN_USERS = {
  'admin': {
    username: 'admin',
    password: 'admin123'
  },
  'manager': {
    username: 'manager',
    password: 'manager456'
  }
};

// Simple session storage (in production, use proper session management)
const sessions = new Map();
const activeUsers = new Set();

// Ensure tmp directory exists
const TMP_DIR = path.join(process.cwd(), 'tmp');
if (!fs.existsSync(TMP_DIR)) {
  fs.mkdirSync(TMP_DIR, { recursive: true });
}

// Utility functions
function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function validateSession(token) {
  return sessions.has(token);
}

function getSessionUser(token) {
  return sessions.get(token);
}

function loadPrograms() {
  try {
    const files = fs.readdirSync(TMP_DIR).filter(file => file.endsWith('.json'));
    const programs = [];
    
    for (const file of files) {
      try {
        const content = fs.readFileSync(path.join(TMP_DIR, file), 'utf8');
        const program = JSON.parse(content);
        programs.push(program);
      } catch (error) {
        console.error(`Error loading program ${file}:`, error);
      }
    }
    
    return programs.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  } catch (error) {
    console.error('Error loading programs:', error);
    return [];
  }
}

function saveProgram(program) {
  try {
    const filename = `${program.id}.json`;
    const filepath = path.join(TMP_DIR, filename);
    fs.writeFileSync(filepath, JSON.stringify(program, null, 2));
    return true;
  } catch (error) {
    console.error('Error saving program:', error);
    return false;
  }
}

function deleteProgram(id) {
  try {
    const filename = `${id}.json`;
    const filepath = path.join(TMP_DIR, filename);
    if (fs.existsSync(filepath)) {
      fs.unlinkSync(filepath);
      return true;
    }
    return false;
  } catch (error) {
    console.error('Error deleting program:', error);
    return false;
  }
}

function loadProgram(id) {
  try {
    const filename = `${id}.json`;
    const filepath = path.join(TMP_DIR, filename);
    if (fs.existsSync(filepath)) {
      const content = fs.readFileSync(filepath, 'utf8');
      return JSON.parse(content);
    }
    return null;
  } catch (error) {
    console.error('Error loading program:', error);
    return null;
  }
}

// Function to serve static files
function serveStaticFile(filePath, res) {
  try {
    const fullPath = path.join(process.cwd(), filePath);
    
    if (!fs.existsSync(fullPath)) {
      res.statusCode = 404;
      res.end('Not Found');
      return;
    }

    const ext = path.extname(filePath);
    const contentTypes = {
      '.html': 'text/html',
      '.css': 'text/css',
      '.js': 'application/javascript',
      '.json': 'application/json',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.gif': 'image/gif',
      '.svg': 'image/svg+xml',
      '.ico': 'image/x-icon'
    };

    const contentType = contentTypes[ext] || 'text/plain';
    const content = fs.readFileSync(fullPath);
    
    res.setHeader('Content-Type', contentType);
    res.statusCode = 200;
    res.end(content);
  } catch (error) {
    console.error('Error serving static file:', error);
    res.statusCode = 500;
    res.end('Internal Server Error');
  }
}

// API Handler
async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { url, method } = req;
  const urlPath = new URL(url, `http://${req.headers.host}`).pathname;
  const pathSegments = urlPath.split('/').filter(Boolean);

  try {
    // Parse request body for POST/PUT requests
    let body = null;
    if (method === 'POST' || method === 'PUT') {
      body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      await new Promise(resolve => {
        req.on('end', () => {
          try {
            body = body ? JSON.parse(body) : {};
          } catch (error) {
            body = {};
          }
          resolve();
        });
      });
    }

    // Routes
    if (pathSegments[1] === 'login' && method === 'POST') {
      // Admin login
      const { username, password } = body;
      
      if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
      }

      const user = ADMIN_USERS[username];
      if (!user || user.password !== password) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const sessionToken = generateSessionToken();
      sessions.set(sessionToken, { username, loginTime: new Date() });
      activeUsers.add(username);

      return res.status(200).json({ 
        success: true, 
        token: sessionToken,
        user: { username }
      });
    }

    if (pathSegments[1] === 'logout' && method === 'POST') {
      // Admin logout
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const user = getSessionUser(token);
        if (user) {
          activeUsers.delete(user.username);
          sessions.delete(token);
        }
      }
      return res.status(200).json({ success: true });
    }

    if (pathSegments[1] === 'stats' && method === 'GET') {
      // Get admin statistics
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const token = authHeader.substring(7);
      if (!validateSession(token)) {
        return res.status(401).json({ error: 'Invalid session' });
      }

      const programs = loadPrograms();
      return res.status(200).json({
        activeUsers: activeUsers.size,
        totalPrograms: programs.length,
        lastUpdate: new Date().toISOString()
      });
    }

    if (pathSegments[1] === 'programs') {
      if (method === 'GET' && pathSegments.length === 2) {
        // Get all programs (public endpoint)
        const programs = loadPrograms();
        // Remove password and sensitive info for public listing
        const publicPrograms = programs.map(({ password, ...program }) => program);
        return res.status(200).json(publicPrograms);
      }

      if (method === 'GET' && pathSegments.length === 3) {
        // Get specific program
        const programId = pathSegments[2];
        const program = loadProgram(programId);
        
        if (!program) {
          return res.status(404).json({ error: 'Program not found' });
        }

        // Check if program has password protection
        if (program.password) {
          const urlParams = new URL(url, `http://${req.headers.host}`);
          const providedPassword = urlParams.searchParams.get('password');
          
          if (!providedPassword || providedPassword !== program.password) {
            return res.status(401).json({ error: 'Password required' });
          }
        }

        // Remove password from response
        const { password, ...publicProgram } = program;
        return res.status(200).json(publicProgram);
      }

      if (method === 'POST') {
        // Create new program (admin only)
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        const token = authHeader.substring(7);
        if (!validateSession(token)) {
          return res.status(401).json({ error: 'Invalid session' });
        }

        const { title, shortDescription, fullDescription, mediaLink, price, contactInfo, programPassword } = body;

        if (!title || !shortDescription || !fullDescription || !contactInfo) {
          return res.status(400).json({ error: 'Required fields missing' });
        }

        const program = {
          id: generateId(),
          title: title.trim(),
          shortDescription: shortDescription.trim(),
          fullDescription: fullDescription.trim(),
          mediaLink: mediaLink ? mediaLink.trim() : null,
          price: price || 'FREE',
          contactInfo: contactInfo.trim(),
          password: programPassword ? programPassword.trim() : null,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };

        if (saveProgram(program)) {
          const { password, ...publicProgram } = program;
          return res.status(201).json(publicProgram);
        } else {
          return res.status(500).json({ error: 'Failed to save program' });
        }
      }

      if (method === 'PUT' && pathSegments.length === 3) {
        // Update program (admin only)
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        const token = authHeader.substring(7);
        if (!validateSession(token)) {
          return res.status(401).json({ error: 'Invalid session' });
        }

        const programId = pathSegments[2];
        const existingProgram = loadProgram(programId);
        
        if (!existingProgram) {
          return res.status(404).json({ error: 'Program not found' });
        }

        const { title, shortDescription, fullDescription, mediaLink, price, contactInfo, programPassword } = body;

        if (!title || !shortDescription || !fullDescription || !contactInfo) {
          return res.status(400).json({ error: 'Required fields missing' });
        }

        const updatedProgram = {
          ...existingProgram,
          title: title.trim(),
          shortDescription: shortDescription.trim(),
          fullDescription: fullDescription.trim(),
          mediaLink: mediaLink ? mediaLink.trim() : null,
          price: price || 'FREE',
          contactInfo: contactInfo.trim(),
          password: programPassword ? programPassword.trim() : null,
          updatedAt: new Date().toISOString()
        };

        if (saveProgram(updatedProgram)) {
          const { password, ...publicProgram } = updatedProgram;
          return res.status(200).json(publicProgram);
        } else {
          return res.status(500).json({ error: 'Failed to update program' });
        }
      }

      if (method === 'DELETE' && pathSegments.length === 3) {
        // Delete program (admin only)
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        const token = authHeader.substring(7);
        if (!validateSession(token)) {
          return res.status(401).json({ error: 'Invalid session' });
        }

        const programId = pathSegments[2];
        
        if (deleteProgram(programId)) {
          return res.status(200).json({ success: true });
        } else {
          return res.status(404).json({ error: 'Program not found' });
        }
      }
    }

    // Default 404 for unmatched routes
    return res.status(404).json({ error: 'Route not found' });

  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

// Create HTTP server
const server = http.createServer(async (req, res) => {
  try {
    const { url } = req;
    
    // Handle API routes
    if (url.startsWith('/api/')) {
      await handler(req, res);
      return;
    }
    
    // Handle static files
    let filePath = url;
    
    // Default to index.html for root
    if (filePath === '/') {
      filePath = '/index.html';
    }
    
    // Remove query parameters for file serving
    filePath = filePath.split('?')[0];
    
    // Remove leading slash
    if (filePath.startsWith('/')) {
      filePath = filePath.substring(1);
    }
    
    serveStaticFile(filePath, res);
  } catch (error) {
    console.error('Server error:', error);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Internal server error' }));
  }
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = handler;

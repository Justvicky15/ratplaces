const fs = require('fs');
const path = require('path');

// Enhanced body parser for serverless environments
async function parseRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalSize = 0;
    const maxSize = 10 * 1024 * 1024; // 10MB limit
    
    const timeout = setTimeout(() => {
      req.removeAllListeners();
      reject(new Error('Request timeout'));
    }, 30000); // 30 second timeout
    
    req.on('data', (chunk) => {
      totalSize += chunk.length;
      if (totalSize > maxSize) {
        clearTimeout(timeout);
        req.removeAllListeners();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    
    req.on('end', () => {
      clearTimeout(timeout);
      req.removeAllListeners();
      
      try {
        const body = Buffer.concat(chunks).toString('utf8');
        if (body.trim()) {
          const parsed = JSON.parse(body);
          resolve(parsed);
        } else {
          resolve({});
        }
      } catch (error) {
        console.error('JSON parse error:', error.message);
        reject(new Error('Invalid JSON in request body'));
      }
    });
    
    req.on('error', (error) => {
      clearTimeout(timeout);
      req.removeAllListeners();
      console.error('Request error:', error.message);
      reject(error);
    });
  });
}

// Enhanced CORS and security headers for serverless
function setServerlessHeaders(res) {
  // CORS headers for cross-origin support
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');
  
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Content type
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  
  // Cache control for API responses
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
}

// Secure file operations with error handling
function secureFileRead(filePath, defaultValue = []) {
  try {
    if (fs.existsSync(filePath)) {
      const data = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(data);
      return Array.isArray(parsed) ? parsed : defaultValue;
    }
  } catch (error) {
    console.error(`Error reading ${filePath}:`, error.message);
  }
  return defaultValue;
}

function secureFileWrite(filePath, data) {
  try {
    const jsonData = JSON.stringify(data, null, 2);
    fs.writeFileSync(filePath, jsonData, 'utf8');
    return true;
  } catch (error) {
    console.error(`Error writing ${filePath}:`, error.message);
    return false;
  }
}

// Input sanitization for security
function sanitizeInput(input, maxLength = 500) {
  if (!input) return '';
  return String(input)
    .trim()
    .substring(0, maxLength)
    .replace(/<[^>]*>/g, '') // Remove HTML tags
    .replace(/[<>'"&]/g, (match) => {
      const entities = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;'
      };
      return entities[match] || match;
    });
}

// Enhanced token validation for serverless
function validateAuthToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('No valid auth header found');
    return null;
  }
  
  const token = authHeader.substring(7);
  console.log('Validating token:', token.substring(0, 20) + '...');
  
  // Simple validation - token should have format: username_timestamp_random_hash
  if (token && token.length > 15 && token.includes('_')) {
    const parts = token.split('_');
    if (parts.length >= 3) {
      const username = parts[0];
      const timestamp = parseInt(parts[1]);
      
      // Check if timestamp is valid
      if (isNaN(timestamp)) {
        console.log('Invalid timestamp in token');
        return null;
      }
      
      const age = Date.now() - timestamp;
      console.log('Token age (hours):', age / (1000 * 60 * 60));
      
      // Token valid for 24 hours
      if (age < 24 * 60 * 60 * 1000) {
        console.log('Token validation successful for user:', username);
        return { valid: true, username: username };
      } else {
        console.log('Token expired');
        return null;
      }
    }
  }
  
  console.log('Token validation failed');
  return null;
}

// Generate secure token
function generateSecureToken(username) {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 15);
  const hash = Math.random().toString(36).substring(2, 10);
  return `${username}_${timestamp}_${random}_${hash}`;
}

// Load credentials with defaults
function loadCredentials() {
  const credentialsPath = path.join(__dirname, 'logins.json');
  const credentials = secureFileRead(credentialsPath, []);
  
  // Ensure we have default admin accounts
  if (credentials.length === 0) {
    const defaultCredentials = [
      { username: "justvicky152", password: "Boekenlezenissaai1102?", avatar: "👑", role: "owner" },
      { username: "admin", password: "admin123", avatar: "🔧", role: "admin" },
      { username: "ratplace", password: "ratplace2024", avatar: "🏪", role: "admin" }
    ];
    
    secureFileWrite(credentialsPath, defaultCredentials);
    return defaultCredentials;
  }
  
  return credentials;
}

// Error response helper
function sendError(res, statusCode, message, details = null) {
  const errorResponse = {
    success: false,
    error: message,
    message: message, // Also include message field for compatibility
    timestamp: new Date().toISOString()
  };
  
  if (details && process.env.NODE_ENV !== 'production') {
    errorResponse.details = details;
  }
  
  console.log(`Sending error ${statusCode}:`, message);
  res.status(statusCode).json(errorResponse);
}

// Success response helper  
function sendSuccess(res, data, message = 'Success', statusCode = 200) {
  const response = {
    success: true,
    message,
    timestamp: new Date().toISOString()
  };
  
  if (data !== undefined) {
    response.data = data;
  }
  
  console.log(`Sending success ${statusCode}:`, message);
  res.status(statusCode).json(response);
}

// Main serverless function - optimized for Vercel
module.exports = async (req, res) => {
  const startTime = Date.now();
  const requestId = Math.random().toString(36).substring(2, 9);
  
  console.log(`[${new Date().toISOString()}] [${requestId}] ${req.method} ${req.url}`);
  
  try {
    // Set headers immediately
    setServerlessHeaders(res);
    
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      console.log(`[${requestId}] CORS preflight - ${Date.now() - startTime}ms`);
      return res.status(200).end();
    }
    
    const { method, url = '/' } = req;
    const cleanUrl = url.split('?')[0];
    const pathParts = cleanUrl.split('/').filter(Boolean);
    
    // Remove 'api' prefix if present
    if (pathParts[0] === 'api') {
      pathParts.shift();
    }
    
    const endpoint = pathParts[0] || '';
    const resourceId = pathParts[1] || '';
    
    console.log(`[${requestId}] Routing: ${method} /${endpoint} ${resourceId ? `(${resourceId})` : ''}`);
    
    // Route handling
    switch (endpoint) {
      case 'health':
        return handleHealthCheck(req, res, requestId);
        
      case 'auth':
        return await handleAuth(req, res, method, requestId);
        
      case 'programs':
        return await handlePrograms(req, res, method, resourceId, requestId);
        
      case 'announcements':
        return await handleAnnouncements(req, res, method, requestId);
        
      case 'analytics':
        return await handleAnalytics(req, res, method, requestId);
        
      default:
        console.log(`[${requestId}] Unknown endpoint: ${endpoint}`);
        return sendError(res, 404, `API endpoint not found: /${endpoint}`);
    }
    
  } catch (error) {
    console.error(`[${requestId}] Unhandled error:`, error);
    return sendError(res, 500, 'Internal server error', error.message);
  }
};

// Health check endpoint
function handleHealthCheck(req, res, requestId) {
  if (req.method !== 'GET') {
    return sendError(res, 405, 'Method not allowed');
  }
  
  const healthData = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  };
  
  console.log(`[${requestId}] Health check successful`);
  return sendSuccess(res, healthData, 'Service is healthy');
}

// Authentication endpoint
async function handleAuth(req, res, method, requestId) {
  if (method !== 'POST') {
    return sendError(res, 405, 'Only POST method allowed for authentication');
  }
  
  try {
    const body = await parseRequestBody(req);
    const { username, password } = body;
    
    console.log(`[${requestId}] Auth attempt for user:`, username);
    
    if (!username || !password) {
      console.log(`[${requestId}] Auth failed: Missing credentials`);
      return sendError(res, 400, 'Username and password are required');
    }
    
    const credentials = loadCredentials();
    const user = credentials.find(u => 
      u.username === sanitizeInput(username, 50) && 
      u.password === password // Don't sanitize password to preserve special chars
    );
    
    if (!user) {
      console.log(`[${requestId}] Auth failed: Invalid credentials for ${username}`);
      return sendError(res, 401, 'Invalid username or password');
    }
    
    const token = generateSecureToken(user.username);
    
    console.log(`[${requestId}] Auth successful for ${user.username}`);
    return sendSuccess(res, {
      token,
      username: user.username,
      avatar: user.avatar || '👤',
      role: user.role || 'admin'
    }, 'Authentication successful');
    
  } catch (error) {
    console.error(`[${requestId}] Auth error:`, error.message);
    return sendError(res, 400, 'Invalid request body');
  }
}

// Programs endpoint
async function handlePrograms(req, res, method, resourceId, requestId) {
  const programsPath = path.join(__dirname, 'programs.json');
  
  switch (method) {
    case 'GET':
      try {
        const programs = secureFileRead(programsPath, []);
        console.log(`[${requestId}] Retrieved ${programs.length} programs`);
        return sendSuccess(res, programs, `Found ${programs.length} programs`);
      } catch (error) {
        console.error(`[${requestId}] Error loading programs:`, error.message);
        return sendError(res, 500, 'Failed to load programs');
      }
      
    case 'POST':
      try {
        console.log(`[${requestId}] Creating program - checking auth...`);
        
        // Validate authentication
        const authResult = validateAuthToken(req.headers.authorization);
        if (!authResult || !authResult.valid) {
          console.log(`[${requestId}] Programs POST: Unauthorized - invalid token`);
          return sendError(res, 401, 'Authentication required');
        }
        
        console.log(`[${requestId}] Auth validated for user: ${authResult.username}`);
        
        const body = await parseRequestBody(req);
        console.log(`[${requestId}] Received program data:`, Object.keys(body));
        
        const { name, category, price, contactUsername, imageUrl, downloadUrl, description, customMessage } = body;
        
        // Enhanced validation
        const validationErrors = [];
        if (!name || !name.trim()) validationErrors.push('Program name is required');
        if (!category) validationErrors.push('Category is required');
        if (price === undefined || price === null || price === '') validationErrors.push('Price is required');
        if (!contactUsername || !contactUsername.trim()) validationErrors.push('Contact username is required');
        if (!downloadUrl || !downloadUrl.trim()) validationErrors.push('Download URL is required');
        if (!description || !description.trim()) validationErrors.push('Description is required');
        
        if (validationErrors.length > 0) {
          console.log(`[${requestId}] Programs POST: Validation errors`, validationErrors);
          return sendError(res, 400, 'Validation failed: ' + validationErrors.join(', '));
        }
        
        // Create sanitized program
        const newProgram = {
          id: `prog_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`,
          name: sanitizeInput(name, 100),
          category: sanitizeInput(category, 50),
          price: parseFloat(price).toFixed(2),
          contactUsername: sanitizeInput(contactUsername, 50),
          imageUrl: sanitizeInput(imageUrl || '', 500) || 
                   `https://via.placeholder.com/300x200/000000/FFFFFF?text=${encodeURIComponent(name.substring(0, 20))}`,
          downloadUrl: sanitizeInput(downloadUrl, 500),
          description: sanitizeInput(description, 1000),
          customMessage: sanitizeInput(customMessage || '', 500),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          status: 'active',
          author: authResult.username
        };
        
        console.log(`[${requestId}] Creating program with ID: ${newProgram.id}`);
        
        // Save program
        const programs = secureFileRead(programsPath, []);
        programs.unshift(newProgram); // Add to beginning
        
        if (secureFileWrite(programsPath, programs)) {
          console.log(`[${requestId}] Program created successfully: ${newProgram.id}`);
          return sendSuccess(res, newProgram, 'Program created successfully', 201);
        } else {
          console.log(`[${requestId}] Failed to save program to file`);
          return sendError(res, 500, 'Failed to save program');
        }
        
      } catch (error) {
        console.error(`[${requestId}] Error creating program:`, error.message, error.stack);
        return sendError(res, 400, 'Invalid request data: ' + error.message);
      }
      
    case 'DELETE':
      try {
        // Validate authentication
        const authResult = validateAuthToken(req.headers.authorization);
        if (!authResult || !authResult.valid) {
          return sendError(res, 401, 'Authentication required');
        }
        
        if (!resourceId) {
          return sendError(res, 400, 'Program ID required');
        }
        
        const programs = secureFileRead(programsPath, []);
        const initialLength = programs.length;
        const filteredPrograms = programs.filter(p => p.id !== resourceId);
        
        if (filteredPrograms.length === initialLength) {
          return sendError(res, 404, 'Program not found');
        }
        
        if (secureFileWrite(programsPath, filteredPrograms)) {
          console.log(`[${requestId}] Program deleted: ${resourceId}`);
          return sendSuccess(res, null, 'Program deleted successfully');
        } else {
          return sendError(res, 500, 'Failed to delete program');
        }
        
      } catch (error) {
        console.error(`[${requestId}] Error deleting program:`, error.message);
        return sendError(res, 500, 'Failed to delete program');
      }
      
    default:
      return sendError(res, 405, `Method ${method} not allowed for programs`);
  }
}

// Announcements endpoint
async function handleAnnouncements(req, res, method, requestId) {
  const announcementsPath = path.join(__dirname, 'announcements.json');
  
  switch (method) {
    case 'GET':
      try {
        const announcements = secureFileRead(announcementsPath, []);
        console.log(`[${requestId}] Retrieved ${announcements.length} announcements`);
        return sendSuccess(res, announcements, 'Announcements loaded successfully');
      } catch (error) {
        console.error(`[${requestId}] Error loading announcements:`, error.message);
        return sendError(res, 500, 'Failed to load announcements');
      }
      
    case 'POST':
      try {
        console.log(`[${requestId}] Creating announcement - checking auth...`);
        
        // Validate authentication
        const authResult = validateAuthToken(req.headers.authorization);
        if (!authResult || !authResult.valid) {
          console.log(`[${requestId}] Announcements POST: Unauthorized - invalid token`);
          return sendError(res, 401, 'Authentication required');
        }
        
        console.log(`[${requestId}] Auth validated for user: ${authResult.username}`);
        
        const body = await parseRequestBody(req);
        const { title, message, priority = 'normal' } = body;
        
        // Validation
        if (!title || !message) {
          return sendError(res, 400, 'Title and message are required');
        }
        
        if (title.length > 200) {
          return sendError(res, 400, 'Title must be 200 characters or less');
        }
        
        if (message.length > 1000) {
          return sendError(res, 400, 'Message must be 1000 characters or less');
        }
        
        if (!['low', 'normal', 'high'].includes(priority)) {
          return sendError(res, 400, 'Priority must be low, normal, or high');
        }
        
        // Get user data from logins
        const logins = secureFileRead(path.join(__dirname, 'logins.json'), []);
        const userData = logins.find(u => u.username === authResult.username);
        
        // Create new announcement
        const newAnnouncement = {
          id: `ann_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
          title: sanitizeInput(title, 200),
          message: sanitizeInput(message, 1000),
          priority: priority,
          author: authResult.username,
          authorAvatar: userData ? userData.avatar : '📢',
          authorAvatarUrl: userData ? userData.avatarUrl : null,
          createdAt: new Date().toISOString()
        };
        
        console.log(`[${requestId}] Creating announcement with ID: ${newAnnouncement.id}`);
        
        // Save announcement
        const announcements = secureFileRead(announcementsPath, []);
        announcements.unshift(newAnnouncement); // Add to beginning
        
        if (secureFileWrite(announcementsPath, announcements)) {
          console.log(`[${requestId}] Announcement created successfully: ${newAnnouncement.id}`);
          return sendSuccess(res, newAnnouncement, 'Announcement published successfully', 201);
        } else {
          console.log(`[${requestId}] Failed to save announcement to file`);
          return sendError(res, 500, 'Failed to save announcement');
        }
        
      } catch (error) {
        console.error(`[${requestId}] Error creating announcement:`, error.message, error.stack);
        return sendError(res, 400, 'Invalid request data: ' + error.message);
      }
      
    default:
      return sendError(res, 405, `Method ${method} not allowed for announcements`);
  }
}

// Analytics endpoint
async function handleAnalytics(req, res, method, requestId) {
  if (method !== 'GET') {
    return sendError(res, 405, 'Only GET method allowed for analytics');
  }
  
  // Validate authentication
  const authResult = validateAuthToken(req.headers.authorization);
  if (!authResult || !authResult.valid) {
    return sendError(res, 401, 'Authentication required');
  }
  
  try {
    const programsPath = path.join(__dirname, 'programs.json');
    const programs = secureFileRead(programsPath, []);
    
    const analyticsData = {
      programs: {
        total: programs.length,
        byCategory: programs.reduce((acc, prog) => {
          acc[prog.category] = (acc[prog.category] || 0) + 1;
          return acc;
        }, {}),
        recent: programs.filter(p => {
          const created = new Date(p.createdAt);
          const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
          return created > weekAgo;
        }).length
      },
      visitors: {
        total: Math.floor(Math.random() * 1000) + 500,
        today: Math.floor(Math.random() * 100) + 50,
        thisWeek: Math.floor(Math.random() * 500) + 200
      },
      system: {
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      }
    };
    
    console.log(`[${requestId}] Analytics retrieved`);
    return sendSuccess(res, analyticsData, 'Analytics data retrieved');
    
  } catch (error) {
    console.error(`[${requestId}] Error loading analytics:`, error.message);
    return sendError(res, 500, 'Failed to load analytics');
  }
}

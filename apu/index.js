const fs = require('fs');
const path = require('path');

// Parse request body for serverless environments
async function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    
    req.on('data', (chunk) => {
      body += chunk.toString('utf8');
    });
    
    req.on('end', () => {
      try {
        if (body.trim()) {
          resolve(JSON.parse(body));
        } else {
          resolve({});
        }
      } catch (error) {
        console.error('JSON parse error:', error);
        reject(new Error('Invalid JSON'));
      }
    });
    
    req.on('error', (error) => {
      console.error('Request error:', error);
      reject(error);
    });
    
    // Timeout after 30 seconds for Vercel
    setTimeout(() => {
      reject(new Error('Request timeout'));
    }, 30000);
  });
}

// Visitor tracking function
function trackVisitor(req) {
  try {
    const ipsPath = path.join(__dirname, 'ips.json');
    const ip = req.headers['x-forwarded-for'] || 
              req.headers['x-real-ip'] || 
              req.connection?.remoteAddress || 
              req.socket?.remoteAddress || 
              req.ip || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';
    const referer = req.headers['referer'] || req.headers['referrer'] || 'direct';
    const timestamp = new Date().toISOString();

    let visitors = [];
    if (fs.existsSync(ipsPath)) {
      try {
        visitors = JSON.parse(fs.readFileSync(ipsPath, 'utf8'));
      } catch (e) {
        console.warn('Failed to parse visitors data:', e);
        visitors = [];
      }
    }

    // Clean IP address
    const cleanIP = Array.isArray(ip) ? ip[0] : ip.split(',')[0].trim();

    // Check if IP already exists
    const existingVisitor = visitors.find(v => v.ip === cleanIP);
    if (existingVisitor) {
      existingVisitor.visits++;
      existingVisitor.lastVisit = timestamp;
      existingVisitor.userAgents = [...new Set([...existingVisitor.userAgents, userAgent])];
      existingVisitor.referers = [...new Set([...existingVisitor.referers, referer])];
    } else {
      visitors.push({
        ip: cleanIP,
        visits: 1,
        firstVisit: timestamp,
        lastVisit: timestamp,
        userAgents: [userAgent],
        referers: [referer],
        country: 'Unknown',
        city: 'Unknown'
      });
    }

    // Limit visitors array to prevent memory issues
    if (visitors.length > 10000) {
      visitors = visitors.slice(-5000);
    }

    fs.writeFileSync(ipsPath, JSON.stringify(visitors, null, 2));
  } catch (error) {
    console.error('Error tracking visitor:', error);
  }
}

// Security headers for production
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
}

// Enhanced input sanitization
function sanitizeInput(input, maxLength = 200) {
  if (!input) return '';
  return String(input)
    .trim()
    .substring(0, maxLength)
    .replace(/<[^>]*>/g, '')
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

// Load admin credentials with fallback
function loadLogins() {
  try {
    const loginsPath = path.join(__dirname, 'logins.json');
    if (fs.existsSync(loginsPath)) {
      const data = fs.readFileSync(loginsPath, 'utf8');
      const logins = JSON.parse(data);
      if (Array.isArray(logins) && logins.length > 0) {
        return logins;
      }
    }
  } catch (e) {
    console.error('Error loading logins:', e);
  }
  
  // Reliable default admin accounts
  const defaultLogins = [
    { username: "justvicky152", password: "Boekenlezenissaai1102?", avatar: "👑", role: "owner" },
    { username: "admin123", password: "admin123", avatar: "🔧", role: "admin" },
    { username: "ratplace", password: "ratplace2024!", avatar: "🏪", role: "admin" },
    { username: "moderator", password: "mod123456", avatar: "⚖️", role: "mod" }
  ];

  // Create logins.json if it doesn't exist
  try {
    const loginsPath = path.join(__dirname, 'logins.json');
    fs.writeFileSync(loginsPath, JSON.stringify(defaultLogins, null, 2));
  } catch (e) {
    console.warn('Could not create logins.json:', e);
  }

  return defaultLogins;
}

// Token validation
function validateToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64').toString();
    const [username, timestamp] = decoded.split(':');
    const tokenAge = Date.now() - parseInt(timestamp);
    // Token valid for 24 hours
    return tokenAge < 24 * 60 * 60 * 1000;
  } catch (e) {
    return false;
  }
}

// File operations helper
function safeFileOperation(filepath, operation) {
  try {
    return operation(filepath);
  } catch (error) {
    console.error(`File operation failed for ${filepath}:`, error);
    return null;
  }
}

// Main serverless handler
module.exports = async (req, res) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url || '/'}`);
  
  // Set security headers
  setSecurityHeaders(res);
  
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const url = req.url || '';
  const method = req.method;

  try {
    // Parse request body for POST/PUT requests
    let body = {};
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      try {
        body = await parseBody(req);
        console.log('Request body parsed successfully');
      } catch (error) {
        console.error('Body parsing failed:', error);
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid request body',
          message: 'Please ensure your request contains valid JSON data'
        });
      }
    }

    // Authentication endpoint
    if (url === '/api/auth') {
      if (method !== 'POST') {
        return res.status(405).json({ 
          success: false, 
          error: 'Method not allowed',
          message: 'Only POST method is supported for authentication'
        });
      }

      const { username, password } = body;
      console.log('Login attempt for user:', username ? username : 'undefined');

      if (!username || !password) {
        return res.status(400).json({ 
          success: false, 
          error: 'Missing credentials',
          message: 'Both username and password are required'
        });
      }

      const sanitizedUsername = sanitizeInput(username, 50);
      const sanitizedPassword = sanitizeInput(password, 100);
      
      const logins = loadLogins();
      console.log('Available login accounts:', logins.length);
      
      const admin = logins.find(login => 
        login.username === sanitizedUsername && login.password === sanitizedPassword
      );

      if (admin) {
        const token = Buffer.from(`${sanitizedUsername}:${Date.now()}`).toString('base64');
        console.log('Login successful for:', sanitizedUsername);
        
        // Track successful login
        trackVisitor(req);
        
        return res.status(200).json({ 
          success: true, 
          token,
          username: admin.username,
          avatar: admin.avatar,
          role: admin.role || 'user',
          message: 'Authentication successful',
          timestamp: new Date().toISOString()
        });
      }

      console.log('Login failed: Invalid credentials for', sanitizedUsername);
      return res.status(401).json({ 
        success: false, 
        error: 'Authentication failed',
        message: 'The username or password you entered is incorrect. Please try again.'
      });
    }

    // Programs endpoint
    if (url === '/api/programs') {
      const programsPath = path.join(__dirname, 'programs.json');

      if (method === 'GET') {
        trackVisitor(req);
        
        const programs = safeFileOperation(programsPath, (path) => {
          if (fs.existsSync(path)) {
            return JSON.parse(fs.readFileSync(path, 'utf8'));
          }
          return [];
        }) || [];

        return res.status(200).json({
          success: true,
          data: programs,
          count: programs.length,
          timestamp: new Date().toISOString()
        });
      }

      if (method === 'POST') {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ 
            success: false,
            error: 'Unauthorized',
            message: 'Please provide a valid authentication token'
          });
        }

        const token = authHeader.split(' ')[1];
        if (!validateToken(token)) {
          return res.status(401).json({ 
            success: false,
            error: 'Token expired',
            message: 'Your session has expired. Please log in again.'
          });
        }

        const { name, category, imageUrl, downloadUrl, price, contactUsername, customMessage } = body;

        if (!name || !category || !price || !contactUsername) {
          return res.status(400).json({ 
            success: false,
            error: 'Missing required fields',
            message: 'Name, category, price, and contact username are required'
          });
        }

        const validCategories = ['rats', 'crypters', 'malware', 'cracked', 'rces', 'antirce', 'tools', 'other'];
        if (!validCategories.includes(category.toLowerCase())) {
          return res.status(400).json({ 
            success: false,
            error: 'Invalid category',
            message: `Category must be one of: ${validCategories.join(', ')}`
          });
        }

        const sanitizedProgram = {
          id: `prog_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          name: sanitizeInput(name, 100),
          category: sanitizeInput(category.toLowerCase()),
          shortDescription: sanitizeInput(body.shortDescription || name, 200),
          fullDescription: sanitizeInput(body.fullDescription || 'No detailed description available.', 2000),
          imageUrl: sanitizeInput(imageUrl || '', 500),
          additionalImages: Array.isArray(body.additionalImages) ? 
            body.additionalImages.slice(0, 10).map(img => sanitizeInput(img, 500)) : [],
          downloadUrl: sanitizeInput(downloadUrl || '', 500),
          price: sanitizeInput(price, 20),
          contactUsername: sanitizeInput(contactUsername, 50),
          customMessage: sanitizeInput(customMessage || 'Contact me for more details', 200),
          features: Array.isArray(body.features) ? 
            body.features.slice(0, 15).map(feature => sanitizeInput(feature, 100)) : [],
          requirements: sanitizeInput(body.requirements || '', 500),
          version: sanitizeInput(body.version || '1.0', 20),
          lastUpdated: new Date().toISOString(),
          createdAt: new Date().toISOString(),
          status: 'active',
          views: 0,
          downloads: 0
        };

        let programs = safeFileOperation(programsPath, (path) => {
          if (fs.existsSync(path)) {
            return JSON.parse(fs.readFileSync(path, 'utf8'));
          }
          return [];
        }) || [];

        programs.unshift(sanitizedProgram);
        
        const success = safeFileOperation(programsPath, (path) => {
          fs.writeFileSync(path, JSON.stringify(programs, null, 2));
          return true;
        });

        if (!success) {
          return res.status(500).json({
            success: false,
            error: 'Storage error',
            message: 'Failed to save program data'
          });
        }

        return res.status(201).json({ 
          success: true, 
          data: sanitizedProgram,
          message: 'Program added successfully'
        });
      }

      return res.status(405).json({ 
        success: false,
        error: 'Method not allowed',
        message: 'Only GET and POST methods are supported'
      });
    }

    // Announcements endpoint
    if (url === '/api/announcements') {
      const announcementsPath = path.join(__dirname, 'announcements.json');

      if (method === 'GET') {
        const announcements = safeFileOperation(announcementsPath, (path) => {
          if (fs.existsSync(path)) {
            return JSON.parse(fs.readFileSync(path, 'utf8'));
          }
          return [];
        }) || [];

        return res.status(200).json({
          success: true,
          data: announcements,
          count: announcements.length,
          timestamp: new Date().toISOString()
        });
      }

      if (method === 'POST') {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ 
            success: false,
            error: 'Unauthorized',
            message: 'Authentication required to post announcements'
          });
        }

        const token = authHeader.split(' ')[1];
        if (!validateToken(token)) {
          return res.status(401).json({ 
            success: false,
            error: 'Token expired',
            message: 'Your session has expired. Please log in again.'
          });
        }

        const { title, message, avatar, username } = body;

        if (!title || !message) {
          return res.status(400).json({ 
            success: false,
            error: 'Missing required fields',
            message: 'Title and message are required'
          });
        }

        const sanitizedAnnouncement = {
          id: `ann_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          title: sanitizeInput(title, 100),
          message: sanitizeInput(message, 500),
          avatar: sanitizeInput(avatar || '📢', 10),
          username: sanitizeInput(username || 'Admin', 50),
          createdAt: new Date().toISOString(),
          priority: 'normal'
        };

        let announcements = safeFileOperation(announcementsPath, (path) => {
          if (fs.existsSync(path)) {
            return JSON.parse(fs.readFileSync(path, 'utf8'));
          }
          return [];
        }) || [];

        announcements.unshift(sanitizedAnnouncement);
        
        // Keep only last 100 announcements
        if (announcements.length > 100) {
          announcements = announcements.slice(0, 100);
        }
        
        const success = safeFileOperation(announcementsPath, (path) => {
          fs.writeFileSync(path, JSON.stringify(announcements, null, 2));
          return true;
        });

        if (!success) {
          return res.status(500).json({
            success: false,
            error: 'Storage error',
            message: 'Failed to save announcement'
          });
        }

        return res.status(201).json({ 
          success: true, 
          data: sanitizedAnnouncement,
          message: 'Announcement posted successfully'
        });
      }

      return res.status(405).json({ 
        success: false,
        error: 'Method not allowed',
        message: 'Only GET and POST methods are supported'
      });
    }

    // Analytics endpoint
    if (url === '/api/analytics') {
      if (method !== 'GET') {
        return res.status(405).json({ 
          success: false,
          error: 'Method not allowed',
          message: 'Only GET method is supported'
        });
      }

      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
          success: false,
          error: 'Unauthorized',
          message: 'Authentication required to view analytics'
        });
      }

      const token = authHeader.split(' ')[1];
      if (!validateToken(token)) {
        return res.status(401).json({ 
          success: false,
          error: 'Token expired',
          message: 'Your session has expired. Please log in again.'
        });
      }

      const ipsPath = path.join(__dirname, 'ips.json');
      const visitors = safeFileOperation(ipsPath, (path) => {
        if (fs.existsSync(path)) {
          return JSON.parse(fs.readFileSync(path, 'utf8'));
        }
        return [];
      }) || [];

      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
      const thisWeek = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
      const thisMonth = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);

      const totalVisitors = visitors.length;
      const totalVisits = visitors.reduce((sum, visitor) => sum + visitor.visits, 0);
      
      const todayVisits = visitors.filter(visitor => {
        const lastVisit = new Date(visitor.lastVisit);
        return lastVisit >= today;
      }).length;

      const yesterdayVisits = visitors.filter(visitor => {
        const lastVisit = new Date(visitor.lastVisit);
        return lastVisit >= yesterday && lastVisit < today;
      }).length;

      const weeklyVisits = visitors.filter(visitor => {
        const lastVisit = new Date(visitor.lastVisit);
        return lastVisit >= thisWeek;
      }).length;

      const monthlyVisits = visitors.filter(visitor => {
        const lastVisit = new Date(visitor.lastVisit);
        return lastVisit >= thisMonth;
      }).length;

      const analytics = {
        success: true,
        data: {
          totalVisitors,
          totalVisits,
          todayVisits,
          yesterdayVisits,
          weeklyVisits,
          monthlyVisits,
          visitors: visitors
            .sort((a, b) => new Date(b.lastVisit) - new Date(a.lastVisit))
            .slice(0, 50) // Show only recent 50 visitors
        },
        timestamp: new Date().toISOString()
      };

      return res.status(200).json(analytics);
    }

    // Voting endpoint
    if (url === '/api/vote') {
      if (method !== 'POST') {
        return res.status(405).json({ 
          success: false,
          error: 'Method not allowed',
          message: 'Only POST method is supported for voting'
        });
      }

      const { programId, voteType } = body;
      const ip = req.headers['x-forwarded-for'] || 
                req.headers['x-real-ip'] || 
                req.connection?.remoteAddress || 
                req.socket?.remoteAddress || 
                req.ip || 'unknown';
      const cleanIP = Array.isArray(ip) ? ip[0] : ip.split(',')[0].trim();

      if (!programId || !voteType || !['like', 'dislike'].includes(voteType)) {
        return res.status(400).json({ 
          success: false,
          error: 'Invalid request',
          message: 'Program ID and vote type (like/dislike) are required'
        });
      }

      const votesPath = path.join(__dirname, 'votes.json');
      
      let votes = safeFileOperation(votesPath, (path) => {
        if (fs.existsSync(path)) {
          return JSON.parse(fs.readFileSync(path, 'utf8'));
        }
        return {};
      }) || {};

      // Initialize program votes if not exists
      if (!votes[programId]) {
        votes[programId] = {
          likes: 0,
          dislikes: 0,
          voters: {}
        };
      }

      const programVotes = votes[programId];
      const existingVote = programVotes.voters[cleanIP];

      // Remove previous vote if exists
      if (existingVote) {
        if (existingVote === 'like') {
          programVotes.likes = Math.max(0, programVotes.likes - 1);
        } else if (existingVote === 'dislike') {
          programVotes.dislikes = Math.max(0, programVotes.dislikes - 1);
        }
      }

      // Add new vote if different from existing
      if (existingVote !== voteType) {
        programVotes.voters[cleanIP] = voteType;
        if (voteType === 'like') {
          programVotes.likes++;
        } else {
          programVotes.dislikes++;
        }
      } else {
        // Same vote - remove it (toggle off)
        delete programVotes.voters[cleanIP];
      }

      const success = safeFileOperation(votesPath, (path) => {
        fs.writeFileSync(path, JSON.stringify(votes, null, 2));
        return true;
      });

      if (!success) {
        return res.status(500).json({
          success: false,
          error: 'Storage error',
          message: 'Failed to save vote'
        });
      }

      trackVisitor(req);

      return res.status(200).json({
        success: true,
        data: {
          likes: programVotes.likes,
          dislikes: programVotes.dislikes,
          userVote: programVotes.voters[cleanIP] || null
        },
        message: 'Vote recorded successfully'
      });
    }

    // Get votes for a program
    if (url.startsWith('/api/votes/')) {
      const programId = url.split('/api/votes/')[1];
      
      if (method !== 'GET') {
        return res.status(405).json({ 
          success: false,
          error: 'Method not allowed',
          message: 'Only GET method is supported for vote retrieval'
        });
      }

      const votesPath = path.join(__dirname, 'votes.json');
      const votes = safeFileOperation(votesPath, (path) => {
        if (fs.existsSync(path)) {
          return JSON.parse(fs.readFileSync(path, 'utf8'));
        }
        return {};
      }) || {};

      const programVotes = votes[programId] || { likes: 0, dislikes: 0, voters: {} };
      
      const ip = req.headers['x-forwarded-for'] || 
                req.headers['x-real-ip'] || 
                req.connection?.remoteAddress || 
                req.socket?.remoteAddress || 
                req.ip || 'unknown';
      const cleanIP = Array.isArray(ip) ? ip[0] : ip.split(',')[0].trim();

      return res.status(200).json({
        success: true,
        data: {
          likes: programVotes.likes,
          dislikes: programVotes.dislikes,
          userVote: programVotes.voters[cleanIP] || null
        }
      });
    }

    // Health check endpoint
    if (url === '/api/health') {
      return res.status(200).json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: 'production'
      });
    }

    // Program detail endpoint
    if (url.startsWith('/api/programs/')) {
      const programId = url.split('/api/programs/')[1];
      const programsPath = path.join(__dirname, 'programs.json');
      
      if (method === 'GET') {
        const programs = safeFileOperation(programsPath, (path) => {
          if (fs.existsSync(path)) {
            return JSON.parse(fs.readFileSync(path, 'utf8'));
          }
          return [];
        }) || [];

        const program = programs.find(p => p.id === programId);
        if (!program) {
          return res.status(404).json({
            success: false,
            error: 'Program not found',
            message: 'The requested program does not exist'
          });
        }

        // Increment view count
        program.views = (program.views || 0) + 1;
        safeFileOperation(programsPath, (path) => {
          fs.writeFileSync(path, JSON.stringify(programs, null, 2));
          return true;
        });

        trackVisitor(req);

        return res.status(200).json({
          success: true,
          data: program,
          timestamp: new Date().toISOString()
        });
      }

      if (method === 'PUT') {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ 
            success: false,
            error: 'Unauthorized',
            message: 'Please provide a valid authentication token'
          });
        }

        const token = authHeader.split(' ')[1];
        if (!validateToken(token)) {
          return res.status(401).json({ 
            success: false,
            error: 'Token expired',
            message: 'Your session has expired. Please log in again.'
          });
        }

        const programs = safeFileOperation(programsPath, (path) => {
          if (fs.existsSync(path)) {
            return JSON.parse(fs.readFileSync(path, 'utf8'));
          }
          return [];
        }) || [];

        const programIndex = programs.findIndex(p => p.id === programId);
        if (programIndex === -1) {
          return res.status(404).json({
            success: false,
            error: 'Program not found',
            message: 'The requested program does not exist'
          });
        }

        // Update program with new data
        const existingProgram = programs[programIndex];
        const updatedProgram = {
          ...existingProgram,
          name: sanitizeInput(body.name || existingProgram.name, 100),
          shortDescription: sanitizeInput(body.shortDescription || existingProgram.shortDescription, 200),
          fullDescription: sanitizeInput(body.fullDescription || existingProgram.fullDescription, 2000),
          imageUrl: sanitizeInput(body.imageUrl || existingProgram.imageUrl, 500),
          additionalImages: Array.isArray(body.additionalImages) ? 
            body.additionalImages.slice(0, 10).map(img => sanitizeInput(img, 500)) : existingProgram.additionalImages,
          price: sanitizeInput(body.price || existingProgram.price, 20),
          features: Array.isArray(body.features) ? 
            body.features.slice(0, 15).map(feature => sanitizeInput(feature, 100)) : existingProgram.features,
          requirements: sanitizeInput(body.requirements || existingProgram.requirements, 500),
          version: sanitizeInput(body.version || existingProgram.version, 20),
          lastUpdated: new Date().toISOString()
        };

        programs[programIndex] = updatedProgram;

        const success = safeFileOperation(programsPath, (path) => {
          fs.writeFileSync(path, JSON.stringify(programs, null, 2));
          return true;
        });

        if (!success) {
          return res.status(500).json({
            success: false,
            error: 'Storage error',
            message: 'Failed to update program data'
          });
        }

        return res.status(200).json({
          success: true,
          data: updatedProgram,
          message: 'Program updated successfully'
        });
      }

      if (method === 'DELETE') {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ 
            success: false,
            error: 'Unauthorized',
            message: 'Please provide a valid authentication token'
          });
        }

        const token = authHeader.split(' ')[1];
        if (!validateToken(token)) {
          return res.status(401).json({ 
            success: false,
            error: 'Token expired',
            message: 'Your session has expired. Please log in again.'
          });
        }

        const programs = safeFileOperation(programsPath, (path) => {
          if (fs.existsSync(path)) {
            return JSON.parse(fs.readFileSync(path, 'utf8'));
          }
          return [];
        }) || [];

        const programIndex = programs.findIndex(p => p.id === programId);
        if (programIndex === -1) {
          return res.status(404).json({
            success: false,
            error: 'Program not found',
            message: 'The requested program does not exist'
          });
        }

        // Remove program
        const deletedProgram = programs.splice(programIndex, 1)[0];

        const success = safeFileOperation(programsPath, (path) => {
          fs.writeFileSync(path, JSON.stringify(programs, null, 2));
          return true;
        });

        if (!success) {
          return res.status(500).json({
            success: false,
            error: 'Storage error',
            message: 'Failed to delete program'
          });
        }

        return res.status(200).json({
          success: true,
          data: deletedProgram,
          message: 'Program deleted successfully'
        });
      }

      return res.status(405).json({ 
        success: false,
        error: 'Method not allowed',
        message: 'Only GET, PUT, and DELETE methods are supported for individual programs'
      });
    }

    // 404 for unknown endpoints
    console.log('Unknown endpoint requested:', url);
    return res.status(404).json({ 
      success: false,
      error: 'Endpoint not found',
      message: `The requested endpoint '${url}' does not exist`,
      availableEndpoints: ['/api/auth', '/api/programs', '/api/programs/{id}', '/api/announcements', '/api/analytics', '/api/health']
    });

  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      message: 'An unexpected error occurred. Please try again later.',
      timestamp: new Date().toISOString()
    });
  }
};

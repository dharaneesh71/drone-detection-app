// server.js - COMPLETE FILE WITH CORS FIX
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const OAuth2 = google.auth.OAuth2;

// --- Load environment variables
const envPath = path.join(__dirname, '.env');
require('dotenv').config({ path: envPath });

// Check if we're in DEMO mode (no email configured)
const DEMO_MODE = !process.env.REFRESH_TOKEN || !process.env.CLIENT_ID || !process.env.CLIENT_SECRET;
const DEMO_OTP = '123456'; // Fixed OTP for demo mode

if (DEMO_MODE) {
  console.log('\n⚠️  RUNNING IN DEMO MODE - Email functionality disabled');
  console.log(`🔐 Use OTP: ${DEMO_OTP} for authentication\n`);
} else {
  console.log('\n✅ Email configuration detected - Full functionality enabled\n');
}

const ENV_PATH = envPath;

// ==== Set up Express application ====
const app = express();
const port = process.env.PORT || 5000;

// ==========================================
// 🔧 CRITICAL: CORS CONFIGURATION MUST BE FIRST
// ==========================================
const corsOptions = {
  origin: [
    'http://localhost:3000',
    'https://drone-detection-app-1.onrender.com',
    'https://drone-detection-app-177.onrender.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  optionsSuccessStatus: 200
};

// Apply CORS middleware FIRST
app.use(cors(corsOptions));

// Handle preflight OPTIONS requests
app.options('*', cors(corsOptions));

// THEN other middleware
app.use(express.json());
app.use('/outputs', express.static(path.join(__dirname, 'outputs')));

// Logging middleware for debugging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  console.log('Origin:', req.headers.origin);
  next();
});

// ==== Helper function to update .env ====
function updateEnvVar(key, value) {
  try {
    let content = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
    const lines = content.split(/\r?\n/);
    const idx = lines.findIndex(l => l.trim().startsWith(`${key}=`));
    const sanitized = String(value).replace(/\r?\n/g, '').trim();
    const newline = `${key}=${sanitized}`;
    
    if (idx >= 0) {
      lines[idx] = newline;
    } else {
      lines.push(newline);
    }
    
    const finalContent = lines.filter(l => l.trim()).join('\n') + '\n';
    fs.writeFileSync(ENV_PATH, finalContent);
    console.log(`[SUCCESS] Updated ${key} in .env`);
    return true;
  } catch (e) {
    console.error('Failed to update .env:', e);
    return false;
  }
}

// --- OAuth configuration (only used when not in DEMO_MODE)
const scopes = ['https://mail.google.com/'];
const redirectUri = 'http://localhost:5000/auth/google/callback';

// ==== Root route ====
app.get('/', (req, res) => {
  res.json({
    status: 'Backend is running',
    demoMode: DEMO_MODE,
    endpoints: {
      test: '/api/test',
      debug: '/api/debug/env',
      requestOtp: '/api/request-otp (POST)',
      verifyOtp: '/api/verify-otp (POST)',
      detectImage: '/api/detect-image (POST)',
      detectVideo: '/api/detect-video (POST)'
    }
  });
});

// ==== OAuth routes (for email configuration) ====
app.get('/auth/google', (req, res) => {
  console.log('[AUTH] Starting OAuth flow...');
  
  if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET) {
    return res.status(500).send(`
      <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .error { background: #f44336; color: white; padding: 20px; border-radius: 5px; }
            .info { background: #2196F3; color: white; padding: 20px; border-radius: 5px; margin-top: 20px; }
            code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; color: #333; }
          </style>
        </head>
        <body>
          <div class="error">
            <h1>Configuration Required</h1>
            <p>Missing CLIENT_ID or CLIENT_SECRET in .env file.</p>
          </div>
          <div class="info">
            <h3>To enable email functionality:</h3>
            <ol>
              <li>Add your Google OAuth credentials to the .env file:
                <ul>
                  <li><code>CLIENT_ID=your_client_id</code></li>
                  <li><code>CLIENT_SECRET=your_client_secret</code></li>
                  <li><code>EMAIL=your_email@gmail.com</code></li>
                  <li><code>RECIPIENT_EMAIL=recipient@gmail.com</code></li>
                </ul>
              </li>
              <li>Restart the server</li>
              <li>Visit this page again to complete OAuth authorization</li>
            </ol>
            <p><strong>Note:</strong> The app will continue to work in DEMO mode with OTP: ${DEMO_OTP}</p>
          </div>
        </body>
      </html>
    `);
  }
  
  const oAuth2Client = new OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    redirectUri
  );
  
  const url = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: scopes,
  });
  
  console.log('[AUTH] Redirecting to Google OAuth...');
  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
  console.log('[AUTH] Received callback from Google');
  
  try {
    if (req.query.error) {
      console.error('[AUTH] Error from Google:', req.query.error);
      return res.status(400).send(`
        <h1>Authorization Failed</h1>
        <p>Error: ${req.query.error}</p>
        <p><a href="/auth/google">Try again</a></p>
      `);
    }
    
    if (!req.query.code) {
      return res.status(400).send(`
        <h1>Authorization Failed</h1>
        <p>No authorization code received.</p>
        <p><a href="/auth/google">Try again</a></p>
      `);
    }
    
    const oAuth2Client = new OAuth2(
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET,
      redirectUri
    );
    
    console.log('[AUTH] Exchanging code for tokens...');
    const { tokens } = await oAuth2Client.getToken(req.query.code);
    
    if (!tokens.refresh_token) {
      return res.status(400).send(`
        <h1>No Refresh Token Received</h1>
        <p>Please revoke access at <a href="https://myaccount.google.com/permissions" target="_blank">Google Account Permissions</a> and try again.</p>
        <p><a href="/auth/google">Authorize Again</a></p>
      `);
    }
    
    const success = updateEnvVar('REFRESH_TOKEN', tokens.refresh_token);
    
    if (success) {
      process.env.REFRESH_TOKEN = tokens.refresh_token;
      require('dotenv').config({ path: envPath, override: true });
      
      console.log('[AUTH] Refresh token saved successfully!');
      
      res.send(`
        <html>
          <head>
            <style>
              body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
              .success { background: #4CAF50; color: white; padding: 20px; border-radius: 5px; }
              .button { background: #2196F3; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; display: inline-block; margin-top: 10px; }
            </style>
          </head>
          <body>
            <div class="success">
              <h1>✅ Success!</h1>
              <p>Email functionality has been enabled!</p>
              <p>The server will now send real OTP codes via email.</p>
            </div>
            <p><strong>Please restart the server for changes to take effect.</strong></p>
            <a href="http://localhost:3000" class="button">Go to Application</a>
          </body>
        </html>
      `);
    } else {
      throw new Error('Failed to save refresh token to .env file');
    }
    
  } catch (e) {
    console.error('[AUTH] Error during token exchange:', e);
    res.status(500).send(`
      <h1>Error</h1>
      <p>${e.message}</p>
      <p><a href="/auth/google">Try again</a></p>
    `);
  }
});

// Debug endpoint
app.get('/api/debug/env', (req, res) => {
  const tok = process.env.REFRESH_TOKEN || '';
  res.json({
    demoMode: DEMO_MODE,
    demoOTP: DEMO_MODE ? DEMO_OTP : null,
    hasRefreshToken: !!tok,
    email: process.env.EMAIL || null,
    recipientEmail: process.env.RECIPIENT_EMAIL || null,
    clientIdPresent: !!process.env.CLIENT_ID,
    clientSecretPresent: !!process.env.CLIENT_SECRET,
  });
});

// Configure storage for uploaded files
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = './uploads';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir);
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// ---- Email transporter (only used when not in DEMO_MODE)
let oauth2Client;

const createTransporter = async () => {
  if (DEMO_MODE) {
    throw new Error('Email functionality not configured. Running in DEMO mode.');
  }

  if (!oauth2Client) {
    oauth2Client = new OAuth2(
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET,
      redirectUri
    );
    oauth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

    oauth2Client.on('tokens', (tokens) => {
      if (tokens.refresh_token) {
        console.log('[INFO] Received new refresh_token, updating .env...');
        updateEnvVar('REFRESH_TOKEN', tokens.refresh_token);
        process.env.REFRESH_TOKEN = tokens.refresh_token;
      }
    });
  }

  const tokenResponse = await oauth2Client.getAccessToken();
  const accessToken = tokenResponse.token;

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      type: 'OAuth2',
      user: process.env.EMAIL,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      refreshToken: process.env.REFRESH_TOKEN,
      accessToken,
    },
  });

  await transporter.verify();
  return transporter;
};

// Send email notification
const sendEmailAlert = async (confidence, detectionType = 'image') => {
  if (DEMO_MODE) {
    console.log('[DEMO] Email alert would be sent (demo mode - no actual email)');
    return true;
  }

  try {
    const transporter = await createTransporter();
    const recipientEmail = process.env.RECIPIENT_EMAIL || process.env.EMAIL;
    
    const mailOptions = {
      from: process.env.EMAIL,
      to: recipientEmail,
      subject: "🚨 Drone Detected!",
      text: `A drone has been detected in a ${detectionType} at ${new Date().toLocaleString()} with confidence ${confidence}.`,
      html: `
        <h2>🚨 Drone Detection Alert</h2>
        <p>A drone has been detected in the monitored area.</p>
        <p><strong>Detection Type:</strong> ${detectionType}</p>
        <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
        <p><strong>Confidence:</strong> ${confidence}</p>
      `
    };
    
    const info = await transporter.sendMail(mailOptions);
    console.log("Email alert sent successfully", info.messageId);
    return true;
  } catch (error) {
    console.error("Error sending email:", error);
    return false;
  }
};

// OTP Storage
const otpStore = {};

// Generate OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Request OTP endpoint
app.post('/api/request-otp', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ success: false, error: "Username is required" });
    }

    // DEMO MODE: Use fixed OTP
    if (DEMO_MODE) {
      console.log(`[DEMO] OTP request for ${username} - using demo OTP: ${DEMO_OTP}`);
      
      otpStore[username] = {
        otp: DEMO_OTP,
        expiresAt: Date.now() + 5 * 60 * 1000,
      };

      return res.json({
        success: true,
        message: "OTP generated (Demo Mode - Check console)",
        expiresAt: otpStore[username].expiresAt,
        demoMode: true,
        demoOTP: DEMO_OTP
      });
    }

    // REAL MODE: Generate and send OTP via email
    const otp = generateOTP();
    otpStore[username] = {
      otp,
      expiresAt: Date.now() + 5 * 60 * 1000,
    };

    console.log('[OTP] Generated OTP for', username, ':', otp);
    
    const transporter = await createTransporter();
    const recipientEmail = process.env.RECIPIENT_EMAIL || process.env.EMAIL;
    
    const mailOptions = {
      from: process.env.EMAIL,
      to: recipientEmail,
      subject: "Your Authentication Code",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Your Authentication Code</h2>
          <p>Use the following code to complete your login:</p>
          <div style="background-color: #f0f0f0; padding: 20px; text-align: center; border-radius: 5px; margin: 20px 0;">
            <h1 style="font-size: 48px; letter-spacing: 8px; margin: 0; color: #333;">${otp}</h1>
          </div>
          <p>This code will expire in 5 minutes.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log("[OTP] Email sent successfully");

    res.json({
      success: true,
      message: "OTP sent to your email",
      expiresAt: otpStore[username].expiresAt
    });

  } catch (error) {
    console.error("[OTP] Error:", error.message);
    res.status(500).json({
      success: false,
      error: "Failed to send OTP. " + (DEMO_MODE ? "Please configure email settings." : error.message)
    });
  }
});

// Verify OTP endpoint
app.post('/api/verify-otp', (req, res) => {
  const { username, otp } = req.body;

  if (!username || !otp) {
    return res.status(400).json({
      success: false,
      error: "Username and OTP are required"
    });
  }

  const storedOTPData = otpStore[username];

  if (!storedOTPData) {
    return res.status(400).json({
      success: false,
      error: "No OTP request found for this user"
    });
  }

  if (Date.now() > storedOTPData.expiresAt) {
    delete otpStore[username];
    return res.status(400).json({
      success: false,
      error: "OTP has expired. Please request a new one."
    });
  }

  if (storedOTPData.otp !== otp) {
    return res.status(400).json({
      success: false,
      error: "Invalid OTP"
    });
  }

  delete otpStore[username];

  res.json({
    success: true,
    message: "OTP verified successfully"
  });
});

// Image detection endpoint
app.post('/api/detect-image', upload.single('image'), async (req, res) => {
  console.log('Image detection request received');
  if (!req.file) {
    return res.status(400).json({ success: false, error: "No file uploaded" });
  }

  const confidence = req.body.confidence || 0.5;
  const inputPath = req.file.path;
  const outputDir = './outputs';
  const outputFilename = `detected_${path.basename(req.file.filename)}`;
  const outputPath = path.join(outputDir, outputFilename);

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir);
  }

  const pythonScriptPath = path.join(__dirname, 'detect.py');

  try {
    const pythonProcess = spawn('py', [
      pythonScriptPath,
      '--input', inputPath,
      '--output', outputPath,
      '--confidence', confidence
    ]);

    let stdoutData = '';
    let stderrData = '';

    pythonProcess.stdout.on('data', (data) => {
      stdoutData += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
      stderrData += data.toString();
    });

    const exitCode = await new Promise((resolve) => {
      pythonProcess.on('close', resolve);
    });

    if (exitCode === 0 && fs.existsSync(outputPath)) {
      const droneDetected = stdoutData.includes("drone") || stdoutData.includes("Found");

      if (droneDetected) {
        await sendEmailAlert(confidence, 'image');
      }

      res.json({
        success: true,
        outputPath: `/outputs/${outputFilename}`,
        droneDetected,
        demoMode: DEMO_MODE
      });
    } else {
      res.status(500).json({
        success: false,
        error: "Processing failed",
        pythonError: stderrData
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Video detection endpoint
app.post('/api/detect-video', upload.single('video'), async (req, res) => {
  console.log('Video detection request received');
  if (!req.file) {
    return res.status(400).json({ success: false, error: "No file uploaded" });
  }

  const confidence = req.body.confidence || 0.5;
  const inputPath = req.file.path;
  const outputDir = './outputs';
  const outputFilename = `detected_${path.basename(req.file.filename)}`;
  const outputPath = path.join(outputDir, outputFilename);

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir);
  }

  const pythonScriptPath = path.join(__dirname, 'detect_video.py');

  try {
    const pythonProcess = spawn('py', [
      pythonScriptPath,
      '--input', inputPath,
      '--output', outputPath,
      '--confidence', confidence
    ]);

    let stdoutData = '';
    let stderrData = '';

    pythonProcess.stdout.on('data', (data) => {
      stdoutData += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
      stderrData += data.toString();
    });

    const exitCode = await new Promise((resolve) => {
      pythonProcess.on('close', resolve);
    });

    if (exitCode === 0 && fs.existsSync(outputPath)) {
      const droneDetected = stdoutData.includes("Drone detected: True") || stdoutData.includes("Found");

      if (droneDetected) {
        await sendEmailAlert(confidence, 'video');
      }

      res.json({
        success: true,
        outputPath: `/outputs/${outputFilename}`,
        droneDetected,
        demoMode: DEMO_MODE
      });
    } else {
      res.status(500).json({
        success: false,
        error: "Processing failed",
        pythonError: stderrData
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Download endpoint
app.get('/download/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'outputs', filename);
  if (fs.existsSync(filePath)) {
    res.download(filePath);
  } else {
    res.status(404).send('File not found');
  }
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    status: 'ok',
    demoMode: DEMO_MODE,
    message: DEMO_MODE ? 'Running in DEMO mode' : 'Email functionality enabled'
  });
});

// Start server
app.listen(port, () => {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`🚀 Server running on port ${port}`);
  console.log(`${'='.repeat(60)}`);
  
  if (DEMO_MODE) {
    console.log(`\n⚠️  DEMO MODE ACTIVE`);
    console.log(`🔐 Use OTP: ${DEMO_OTP} for authentication`);
    console.log(`\n📧 To enable email functionality:`);
    console.log(`   1. Add credentials to .env file`);
    console.log(`   2. Visit: http://localhost:${port}/auth/google`);
    console.log(`   3. Restart the server`);
  } else {
    console.log(`\n✅ Email functionality enabled`);
  }
  
  console.log(`\n🔗 Endpoints:`);
  console.log(`   - http://localhost:${port}/api/test`);
  console.log(`   - http://localhost:${port}/api/debug/env`);
  console.log(`${'='.repeat(60)}\n`);
});
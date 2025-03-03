// server.js
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const OAuth2 = google.auth.OAuth2;
require('dotenv').config();

// Set up Express application
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/outputs', express.static(path.join(__dirname, 'outputs')));

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

const upload = multer({ storage: storage });

// Updated OAuth2 setup for email
const createTransporter = async () => {
    try {
        // Check if we have all required environment variables
        const requiredVars = ['CLIENT_ID', 'CLIENT_SECRET', 'REFRESH_TOKEN', 'EMAIL'];
        const missingVars = requiredVars.filter(name => !process.env[name]);

        if (missingVars.length > 0) {
            console.error(`Missing required environment variables: ${missingVars.join(', ')}`);
            throw new Error('Missing required environment variables');
        }

        const oauth2Client = new OAuth2(
            process.env.CLIENT_ID,
            process.env.CLIENT_SECRET,
            "https://developers.google.com/oauthplayground"
        );

        oauth2Client.setCredentials({
            refresh_token: process.env.REFRESH_TOKEN
        });

        const accessToken = await new Promise((resolve, reject) => {
            oauth2Client.getAccessToken((err, token) => {
                if (err) {
                    console.error("Failed to get access token", err);
                    reject(err);
                }
                resolve(token);
            });
        });

        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                type: "OAuth2",
                user: process.env.EMAIL,
                accessToken,
                clientId: process.env.CLIENT_ID,
                clientSecret: process.env.CLIENT_SECRET,
                refreshToken: process.env.REFRESH_TOKEN
            }
        });

        return transporter;
    } catch (error) {
        console.error("Error creating email transporter:", error);
        throw error;
    }
};

// Send email notification
const sendEmailAlert = async (confidence, detectionType = 'image') => {
    try {
        const transporter = await createTransporter();

        const recipientEmail = process.env.RECIPIENT_EMAIL || "recipient@gmail.com";

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
                <p>Please review the detection in the Drone Detection System dashboard.</p>
            `
        };

        const info = await transporter.sendMail(mailOptions);
        console.log("Email alert sent successfully", info.messageId);
        return true;
    } catch (error) {
        console.error("Error sending email:", error);
        // Don't throw the error, return false to indicate failure without stopping the app
        return false;
    }
};

// Debug middleware to log requests
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});


// Add these routes to your server.js file

const otpStore = {}; // In-memory storage for OTPs (use a database in production)

// Function to generate a random 6-digit OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Route to request an OTP
app.post('/api/request-otp', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ success: false, error: "Username is required" });
        }

        // In a real app, verify the username exists in your database first

        // Generate OTP
        const otp = generateOTP();

        // Store OTP with expiration time (5 minutes)
        otpStore[username] = {
            otp,
            expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes from now
        };

        // Create email content
        const transporter = await createTransporter();

        const recipientEmail = process.env.RECIPIENT_EMAIL || "dharaneesh2004@gmail.com"; // Using your variable

        const mailOptions = {
            from: process.env.EMAIL,
            to: recipientEmail,
            subject: "Your Authentication Code",
            text: `Your OTP code is: ${otp}. This code will expire in 5 minutes.`,
            html: `
        <h2>Your Authentication Code</h2>
        <p>Use the following code to complete your login:</p>
        <h1 style="font-size: 32px; letter-spacing: 5px; background-color: #f0f0f0; padding: 10px; display: inline-block;">${otp}</h1>
        <p>This code will expire in 5 minutes.</p>
        <p>If you did not request this code, please ignore this email.</p>
      `
        };

        // Send the email
        const info = await transporter.sendMail(mailOptions);
        console.log("OTP email sent successfully", info.messageId);

        res.json({
            success: true,
            message: "OTP sent successfully",
            expiresAt: otpStore[username].expiresAt
        });

    } catch (error) {
        console.error("Error sending OTP:", error);
        res.status(500).json({
            success: false,
            error: "Failed to send OTP"
        });
    }
});

// Route to verify an OTP
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
        // Clear expired OTP
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

    // Clear used OTP
    delete otpStore[username];

    // In a real app, you would create and return a JWT token here

    res.json({
        success: true,
        message: "OTP verified successfully",
        token: "jwt-token-would-go-here" // Replace with actual JWT in production
    });
});

// Route for image detection
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

    console.log(`Processing image: ${inputPath}`);
    console.log(`Output will be saved to: ${outputPath}`);
    console.log(`Confidence threshold: ${confidence}`);

    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir);
    }

    // Check if Python script exists
    const pythonScriptPath = path.join(__dirname, 'detect.py');
    if (!fs.existsSync(pythonScriptPath)) {
        return res.status(500).json({
            success: false,
            error: `Python script not found: ${pythonScriptPath}`
        });
    }

    // For testing, create a simple output without running Python
    if (process.env.NODE_ENV === 'test') {
        // Copy the input file to output for testing purposes
        fs.copyFileSync(inputPath, outputPath);
        return res.json({
            success: true,
            outputPath: `/outputs/${outputFilename}`,
            droneDetected: true,
            message: "Test mode: Simulated detection"
        });
    }

    try {
        // Run YOLOv8 Python process
        const pythonProcess = spawn('python', [
            pythonScriptPath,
            '--input', inputPath,
            '--output', outputPath,
            '--confidence', confidence
        ]);

        let stdoutData = '';
        let stderrData = '';

        pythonProcess.stdout.on('data', (data) => {
            stdoutData += data.toString();
            console.log(`Python stdout: ${data}`);
        });

        pythonProcess.stderr.on('data', (data) => {
            stderrData += data.toString();
            console.error(`Python stderr: ${data}`);
        });

        const exitCode = await new Promise((resolve) => {
            pythonProcess.on('close', resolve);
        });

        console.log(`Python process exited with code ${exitCode}`);

        if (exitCode === 0) {
            // Check if output file was created
            if (!fs.existsSync(outputPath)) {
                return res.status(500).json({
                    success: false,
                    error: "Output file was not created",
                    pythonOutput: stdoutData,
                    pythonError: stderrData
                });
            }

            // Check for drone detection in Python output
            const droneDetected = stdoutData.includes("drone") || stdoutData.includes("Found");

            if (droneDetected) {
                try {
                    await sendEmailAlert(confidence, 'image');
                    console.log("Email alert sent");
                } catch (error) {
                    console.error("Failed to send email alert:", error);
                }
            }

            res.json({
                success: true,
                outputPath: `/outputs/${outputFilename}`,
                droneDetected,
                message: stdoutData
            });
        } else {
            res.status(500).json({
                success: false,
                error: "Python processing failed",
                exitCode,
                pythonOutput: stdoutData,
                pythonError: stderrData
            });
        }
    } catch (error) {
        console.error("Error in image detection process:", error);
        res.status(500).json({
            success: false,
            error: error.message || "An unexpected error occurred",
        });
    }
});

// Route for video detection
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

    console.log(`Processing video: ${inputPath}`);
    console.log(`Output will be saved to: ${outputPath}`);
    console.log(`Confidence threshold: ${confidence}`);

    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir);
    }

    // Check if Python script exists
    const pythonScriptPath = path.join(__dirname, 'detect_video.py');
    if (!fs.existsSync(pythonScriptPath)) {
        return res.status(500).json({
            success: false,
            error: `Python script not found: ${pythonScriptPath}`
        });
    }

    // For testing, create a simple output without running Python
    if (process.env.NODE_ENV === 'test') {
        // Copy the input file to output for testing purposes
        fs.copyFileSync(inputPath, outputPath);
        return res.json({
            success: true,
            outputPath: `/outputs/${outputFilename}`,
            droneDetected: true,
            message: "Test mode: Simulated detection"
        });
    }

    try {
        // Run YOLOv8 Python process
        const pythonProcess = spawn('python', [
            pythonScriptPath,
            '--input', inputPath,
            '--output', outputPath,
            '--confidence', confidence
        ]);

        let stdoutData = '';
        let stderrData = '';

        pythonProcess.stdout.on('data', (data) => {
            stdoutData += data.toString();
            console.log(`Python stdout: ${data}`);

            // Send progress updates to the client if possible
            // This would require WebSockets for real-time updates
        });

        pythonProcess.stderr.on('data', (data) => {
            stderrData += data.toString();
            console.error(`Python stderr: ${data}`);
        });

        const exitCode = await new Promise((resolve) => {
            pythonProcess.on('close', resolve);
        });

        console.log(`Python process exited with code ${exitCode}`);

        if (exitCode === 0) {
            // Check if output file was created
            if (!fs.existsSync(outputPath)) {
                return res.status(500).json({
                    success: false,
                    error: "Output file was not created",
                    pythonOutput: stdoutData,
                    pythonError: stderrData
                });
            }

            // Check for drone detection in Python output
            const droneDetected = stdoutData.includes("Drone detected: True") ||
                stdoutData.includes("Found");

            if (droneDetected) {
                try {
                    await sendEmailAlert(confidence, 'video');
                    console.log("Email alert sent");
                } catch (error) {
                    console.error("Failed to send email alert:", error);
                }
            }

            res.json({
                success: true,
                outputPath: `/outputs/${outputFilename}`,
                droneDetected,
                message: stdoutData
            });
        } else {
            res.status(500).json({
                success: false,
                error: "Python processing failed",
                exitCode,
                pythonOutput: stdoutData,
                pythonError: stderrData
            });
        }
    } catch (error) {
        console.error("Error in video detection process:", error);
        res.status(500).json({
            success: false,
            error: error.message || "An unexpected error occurred",
        });
    }
});

// Add a simple test endpoint
app.get('/api/test', (req, res) => {
    res.json({
        status: 'Server is running',
        time: new Date().toISOString(),
        pythonAvailable: fs.existsSync(path.join(__dirname, 'detect.py'))
    });
});

// Add this route for direct downloads
app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'outputs', filename);

    if (fs.existsSync(filePath)) {
        res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
        res.setHeader('Content-Type', 'video/mp4');
        fs.createReadStream(filePath).pipe(res);
    } else {
        res.status(404).send('File not found');
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`- Testing endpoint: http://localhost:${port}/api/test`);
    console.log(`- To test the image detection: POST to http://localhost:${port}/api/detect-image`);
    console.log(`- To test the video detection: POST to http://localhost:${port}/api/detect-video`);
    console.log(`- To request OTP: POST to http://localhost:${port}/api/request-otp`);
    console.log(`- To verify OTP: POST to http://localhost:${port}/api/verify-otp`);
});
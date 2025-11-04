// src/App.js
import React, { useState, useRef, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate, useNavigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

// API Configuration
const API_BASE_URL = 'https://drone-detection-app-177.onrender.com';


// Consolidated MUI component imports
import {
  AppBar, Toolbar, Typography, Container, Paper, Slider,
  FormControl, RadioGroup, FormControlLabel, Radio, Button,
  Box, Table, TableBody, TableCell, TableContainer, TableHead,
  TableRow, Alert, Card, CardContent, List, ListItem, ListItemIcon,
  ListItemText, Divider, IconButton, TextField, InputAdornment,
  Avatar, Menu, MenuItem, Drawer, useMediaQuery, Grid, Chip,
  CircularProgress, Dialog, DialogTitle, DialogContent, LinearProgress
} from '@mui/material';

// Consolidated icon imports
import {
  Info as InfoIcon,
  PhotoCamera as CameraIcon,
  Videocam as VideoIcon,
  ViewList as ListIcon,
  Send as SendIcon,
  CheckCircle as CheckCircleIcon,
  ArrowRight as ArrowRightIcon,
  Person as PersonIcon,
  Lock as LockIcon,
  Menu as MenuIcon,
  ExitToApp as LogoutIcon,
  Dashboard as DashboardIcon,
  Settings as SettingsIcon,
  Notifications as NotificationsIcon,
  AccountCircle as AccountCircleIcon,
  Security as SecurityIcon,
  Search as SearchIcon,
  VerifiedUser as VerifiedUserIcon
} from '@mui/icons-material';

// Define theme with custom colors
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#4dabf5',
    },
    secondary: {
      main: '#f48fb1',
    },
    background: {
      default: '#0a1929',
      paper: '#132f4c',
    },
    success: {
      main: '#4caf50',
    },
    warning: {
      main: '#ff9800',
    },
    error: {
      main: '#f44336',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h4: {
      fontWeight: 600,
    },
    h5: {
      fontWeight: 500,
    },
  },
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          borderRadius: 8,
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          borderRadius: 12,
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          boxShadow: '0 8px 16px 0 rgba(0,0,0,0.2)',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
          background: 'linear-gradient(90deg, #1e3c72 0%, #2a5298 100%)',
        },
      },
    },
  },
});

// REMOVE ALL DUPLICATE IMPORTS HERE - Delete lines 113-116 completely

// Add this code to replace the Login component in App.js
// Only showing the updated parts - keep all other code the same

function Login({ setIsAuthenticated, setUser }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showOtpModal, setShowOtpModal] = useState(false);
  const [otp, setOtp] = useState('');
  const [otpExpiry, setOtpExpiry] = useState(null);
  const [otpError, setOtpError] = useState('');
  const [otpLoading, setOtpLoading] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const [otpSuccess, setOtpSuccess] = useState(false);
  const [demoMode, setDemoMode] = useState(false); // NEW: Track demo mode
  const [demoOTP, setDemoOTP] = useState(null); // NEW: Store demo OTP
  const navigate = useNavigate();

  // Countdown timer for OTP expiration
  useEffect(() => {
    let timer;
    if (countdown > 0) {
      timer = setTimeout(() => setCountdown(countdown - 1), 1000);
    }
    return () => clearTimeout(timer);
  }, [countdown]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  // Replace your handleLogin function with this version:

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (!username || !password) {
      setError('Please enter both username and password');
      setLoading(false);
      return;
    }

    try {
      if (username === "dharaneesh" && password === "1234") {
        console.log('Attempting to request OTP...'); // Debug log
        
        const response = await fetch('https://drone-detection-app-177.onrender.com/api/request-otp', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ username }),
        });

        console.log('Response status:', response.status); // Debug log

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log('Response data:', data); // Debug log

        if (data.success) {
          const expiryTime = new Date(data.expiresAt);
          const currentTime = new Date();
          const secondsRemaining = Math.floor((expiryTime - currentTime) / 1000);

          setCountdown(secondsRemaining);
          setOtpExpiry(data.expiresAt);
          setDemoMode(data.demoMode || false);
          setDemoOTP(data.demoOTP || null);
          setShowOtpModal(true);
        } else {
          setError(data.error || 'Failed to send OTP. Please try again.');
        }
      } else {
        setError('Invalid credentials');
      }
    } catch (err) {
      console.error('Login error:', err);
      setError(`Connection error: ${err.message}. Please check if backend is running.`);
    } finally {
      setLoading(false);
    }
  };

  const verifyOtp = async () => {
    if (!otp) {
      setOtpError('Please enter the OTP');
      return;
    }

    setOtpLoading(true);
    setOtpError('');

    try {
      const response = await fetch('https://drone-detection-app-177.onrender.com/api/verify-otp', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, otp }),
      });

      const data = await response.json();

      if (data.success) {
        setOtpSuccess(true);

        const userData = {
          name: username,
          avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=random&color=fff`
        };

        localStorage.setItem('user', JSON.stringify(userData));
        localStorage.setItem('isAuthenticated', 'true');

        setTimeout(() => {
          setUser(userData);
          setIsAuthenticated(true);
          navigate('/');
        }, 4000);
      } else {
        setOtpError(data.error || 'Invalid OTP. Please try again.');
      }
    } catch (err) {
      console.error('OTP verification error:', err);
      setOtpError('An error occurred. Please try again.');
    } finally {
      setOtpLoading(false);
    }
  };

  const requestNewOtp = async () => {
    setOtpLoading(true);
    setOtpError('');

    try {
      const response = await fetch('https://drone-detection-app-177.onrender.com/api/request-otp', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username }),
      });

      const data = await response.json();

      if (data.success) {
        const expiryTime = new Date(data.expiresAt);
        const currentTime = new Date();
        const secondsRemaining = Math.floor((expiryTime - currentTime) / 1000);

        setCountdown(secondsRemaining);
        setOtpExpiry(data.expiresAt);
        setDemoMode(data.demoMode || false);
        setDemoOTP(data.demoOTP || null);
        setOtp('');
        setOtpError('');
      } else {
        setOtpError(data.error || 'Failed to send new OTP. Please try again.');
      }
    } catch (err) {
      console.error('Request new OTP error:', err);
      setOtpError('An error occurred. Please try again.');
    } finally {
      setOtpLoading(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundImage: 'url(https://images.unsplash.com/photo-1527977966376-1c8408f9f108?q=80&w=2000)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        position: 'relative',
        '&::before': {
          content: '""',
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.7)',
          backdropFilter: 'blur(5px)',
        }
      }}
    >
      <Container maxWidth="sm" sx={{ position: 'relative', zIndex: 1 }}>
        <Card sx={{ p: 4, backdropFilter: 'blur(10px)', backgroundColor: 'rgba(19, 47, 76, 0.9)' }}>
          <Box sx={{ textAlign: 'center', mb: 4 }}>
            <img
              src="https://images.pexels.com/photos/442587/pexels-photo-442587.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750"
              alt="Drone Detection System Logo"
              style={{ width: '80px', height: '80px', objectFit: 'cover', borderRadius: '50%' }}
            />
            <Typography variant="h4" sx={{ mt: 2, color: '#fff', fontWeight: 'bold' }}>
              Drone Detection System
            </Typography>
            <Typography variant="body1" sx={{ mt: 1, color: '#bbb' }}>
              Sign in to access the advanced AI-powered drone detection platform
            </Typography>
          </Box>

          <Box component="form" onSubmit={handleLogin}>
            <TextField
              margin="normal"
              required
              fullWidth
              id="username"
              label="Username"
              name="username"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <PersonIcon color="primary" />
                  </InputAdornment>
                ),
              }}
              sx={{
                mb: 3,
                '& .MuiOutlinedInput-root': {
                  '& fieldset': {
                    borderColor: 'rgba(255, 255, 255, 0.3)',
                  },
                  '&:hover fieldset': {
                    borderColor: 'rgba(255, 255, 255, 0.5)',
                  },
                  '&.Mui-focused fieldset': {
                    borderColor: '#4dabf5',
                  },
                },
              }}
            />
            <TextField
              margin="normal"
              required
              fullWidth
              name="password"
              label="Password"
              type="password"
              id="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <LockIcon color="primary" />
                  </InputAdornment>
                ),
              }}
              sx={{
                mb: 3,
                '& .MuiOutlinedInput-root': {
                  '& fieldset': {
                    borderColor: 'rgba(255, 255, 255, 0.3)',
                  },
                  '&:hover fieldset': {
                    borderColor: 'rgba(255, 255, 255, 0.5)',
                  },
                  '&.Mui-focused fieldset': {
                    borderColor: '#4dabf5',
                  },
                },
              }}
            />

            {error && (
              <Alert severity="error" sx={{ mb: 3 }}>
                {error}
              </Alert>
            )}

            <Button
              type="submit"
              fullWidth
              variant="contained"
              disabled={loading}
              sx={{
                py: 1.5,
                fontSize: '1rem',
                fontWeight: 'bold',
                background: 'linear-gradient(90deg, #1e3c72 0%, #2a5298 100%)',
                '&:hover': {
                  background: 'linear-gradient(90deg, #2a5298 0%, #1e3c72 100%)',
                }
              }}
            >
              {loading ? "Authenticating..." : "Sign In"}
            </Button>

            <Box sx={{ mt: 3, textAlign: 'center' }}>
              <Typography variant="body2" color="text.secondary">
                For demo: username "dharaneesh" and password "1234"
              </Typography>
            </Box>
          </Box>
        </Card>
      </Container>

      {/* OTP Verification Modal */}
      <Dialog
        open={showOtpModal}
        onClose={() => { }}
        PaperProps={{
          sx: {
            backgroundColor: 'rgba(19, 47, 76, 0.95)',
            backdropFilter: 'blur(10px)',
            borderRadius: 2,
            maxWidth: 400
          }
        }}
      >
        <DialogTitle sx={{ textAlign: 'center', color: '#fff', fontWeight: 'bold' }}>
          {otpSuccess ? "Authentication Successful" : "Two-Factor Authentication"}
        </DialogTitle>
        <DialogContent>
          {otpSuccess ? (
            // Success message UI
            <Box sx={{ textAlign: 'center', my: 3 }}>
              <CheckCircleIcon sx={{ fontSize: 80, color: '#4CAF50', mb: 2 }} />
              <Typography variant="h6" sx={{ color: '#fff', fontWeight: 'bold', mb: 1 }}>
                OTP Verified Successfully!
              </Typography>
              <Typography sx={{ color: '#bbb' }}>
                Redirecting to dashboard...
              </Typography>
              <LinearProgress sx={{ mt: 3 }} />
            </Box>
          ) : (
            // OTP entry UI
            <>
              {/* NEW: Demo Mode Alert */}
              {demoMode && demoOTP && (
                <Alert 
                  severity="info" 
                  sx={{ mb: 2 }}
                  icon={<InfoIcon />}
                >
                  <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 0.5 }}>
                    🎯 Demo Mode Active
                  </Typography>
                  <Typography variant="body2">
                    Use OTP: <strong style={{ fontSize: '1.1em', letterSpacing: '2px' }}>{demoOTP}</strong>
                  </Typography>
                  <Typography variant="caption" sx={{ display: 'block', mt: 1 }}>
                    Configure email in .env to receive real OTP codes
                  </Typography>
                </Alert>
              )}

              <Box sx={{ textAlign: 'center', mb: 3 }}>
                <VerifiedUserIcon sx={{ fontSize: 64, color: '#4dabf5', mb: 2 }} />
                <Typography sx={{ color: '#bbb' }}>
                  {demoMode 
                    ? "Enter the demo OTP code shown above"
                    : "A verification code has been sent to dharaneesh2004@gmail.com"
                  }
                </Typography>
                {countdown > 0 && (
                  <Typography variant="body2" sx={{ mt: 1, color: '#f8bb86' }}>
                    Code expires in: {formatTime(countdown)}
                  </Typography>
                )}
              </Box>

              <TextField
                autoFocus
                margin="dense"
                label="Enter 6-digit verification code"
                type="text"
                fullWidth
                variant="outlined"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                inputProps={{ maxLength: 6, inputMode: 'numeric', pattern: '[0-9]*' }}
                sx={{
                  mb: 2,
                  '& .MuiOutlinedInput-root': {
                    '& fieldset': {
                      borderColor: 'rgba(255, 255, 255, 0.3)',
                    },
                    '&:hover fieldset': {
                      borderColor: 'rgba(255, 255, 255, 0.5)',
                    },
                    '&.Mui-focused fieldset': {
                      borderColor: '#4dabf5',
                    },
                  },
                }}
              />

              {otpError && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  {otpError}
                </Alert>
              )}

              <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 2 }}>
                <Button
                  onClick={requestNewOtp}
                  disabled={otpLoading || countdown > 0}
                  sx={{ color: countdown > 0 ? 'grey.500' : '#4dabf5' }}
                >
                  Resend Code
                </Button>
                <Button
                  onClick={verifyOtp}
                  variant="contained"
                  disabled={otpLoading}
                  sx={{
                    background: 'linear-gradient(90deg, #1e3c72 0%, #2a5298 100%)',
                    '&:hover': {
                      background: 'linear-gradient(90deg, #2a5298 0%, #1e3c72 100%)',
                    }
                  }}
                >
                  {otpLoading ? "Verifying..." : "Verify"}
                </Button>
              </Box>
            </>
          )}
        </DialogContent>
      </Dialog>
    </Box>
  );
}
// About Component with improved UI
function About() {
  return (
    <Container maxWidth="lg" sx={{ mt: 4 }}>
      <Card sx={{ overflow: 'hidden', mb: 4 }}>
        <Box sx={{
          position: 'relative',
          height: '200px',
          overflow: 'hidden',
          backgroundImage: 'url(https://images.unsplash.com/photo-1507582020474-9a35b7d455d9?q=80&w=1470)',
          backgroundSize: 'cover',
          backgroundPosition: 'center'
        }}>
          <Box sx={{
            position: 'absolute',
            bottom: 0,
            left: 0,
            right: 0,
            p: 3,
            background: 'linear-gradient(to top, rgba(0,0,0,0.8), transparent)'
          }}>
            <Typography variant="h4" sx={{ color: 'white', fontWeight: 'bold' }}>
              Drone Detection System
            </Typography>
            <Chip
              icon={<SecurityIcon />}
              label="Advanced Protection"
              color="primary"
              sx={{ mt: 1 }}
            />
          </Box>
        </Box>

        <CardContent sx={{ p: 4 }}>
          <Typography variant="body1" paragraph sx={{ fontSize: '1.1rem' }}>
            <strong>Advanced Drone Detection System using YOLOv8.</strong>
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={4}>
              <Card sx={{ height: '100%', p: 2, background: 'linear-gradient(45deg, #132f4c 30%, #1e3c72 90%)' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <CameraIcon color="primary" sx={{ fontSize: 40, mr: 2 }} />
                    <Typography variant="h6">Image & Video Detection</Typography>
                  </Box>
                  <Typography variant="body2">
                    Upload images or videos for instant drone detection with our sophisticated AI model.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={4}>
              <Card sx={{ height: '100%', p: 2, background: 'linear-gradient(45deg, #132f4c 30%, #1e3c72 90%)' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <SettingsIcon color="primary" sx={{ fontSize: 40, mr: 2 }} />
                    <Typography variant="h6">Adjustable Confidence</Typography>
                  </Box>
                  <Typography variant="body2">
                    Fine-tune detection sensitivity to match your security requirements and environment.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={4}>
              <Card sx={{ height: '100%', p: 2, background: 'linear-gradient(45deg, #132f4c 30%, #1e3c72 90%)' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <NotificationsIcon color="primary" sx={{ fontSize: 40, mr: 2 }} />
                    <Typography variant="h6">Email Alerts</Typography>
                  </Box>
                  <Typography variant="body2">
                    Receive immediate notifications when unauthorized drones are detected in your airspace.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          <Typography variant="h5" gutterBottom sx={{ mt: 4, borderBottom: '2px solid #4dabf5', pb: 1 }}>
            📌 About the Drone Detection System
          </Typography>
          <Typography variant="body1" paragraph>
            Welcome to the Advanced Drone Detection System, designed to detect unauthorized drones in restricted airspaces,
            military zones, and critical infrastructure areas. Using the advanced YOLOv8 model, this system provides real-time
            image and video analysis, ensuring enhanced security and surveillance.
          </Typography>

          <Typography variant="h5" gutterBottom sx={{ mt: 4, borderBottom: '2px solid #4dabf5', pb: 1 }}>
            🚀 Key Features
          </Typography>
          <List>
            <ListItem>
              <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
              <ListItemText
                primary="High-Accuracy AI Model"
                secondary="Utilizes YOLOv8 for precise drone detection with minimal false positives."
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
              <ListItemText
                primary="Image & Video Analysis"
                secondary="Supports both formats for comprehensive monitoring of your airspace."
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
              <ListItemText
                primary="Adjustable Confidence Threshold"
                secondary="Customize detection sensitivity to balance between detection rate and false alarms."
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
              <ListItemText
                primary="Automated Email Alerts"
                secondary="Instant notifications upon drone detection for rapid response."
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
              <ListItemText
                primary="Detection Logs"
                secondary="Maintain a detailed history of past detections for security analysis and reporting."
              />
            </ListItem>
          </List>

          <Typography variant="h5" gutterBottom sx={{ mt: 4, borderBottom: '2px solid #4dabf5', pb: 1 }}>
            ⚠️ Why Drone Detection Matters
          </Typography>
          <Grid container spacing={2} sx={{ mt: 2 }}>
            <Grid item xs={12} md={4}>
              <Card sx={{ height: '100%', background: 'rgba(255, 152, 0, 0.1)' }}>
                <CardContent>
                  <Typography variant="h6" color="warning.main" gutterBottom>
                    Security Threats
                  </Typography>
                  <Typography variant="body2">
                    Prevents unauthorized drone activity in sensitive and restricted airspaces.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card sx={{ height: '100%', background: 'rgba(255, 152, 0, 0.1)' }}>
                <CardContent>
                  <Typography variant="h6" color="warning.main" gutterBottom>
                    Military Protection
                  </Typography>
                  <Typography variant="body2">
                    Enhances military & homeland security by detecting potential aerial threats.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card sx={{ height: '100%', background: 'rgba(255, 152, 0, 0.1)' }}>
                <CardContent>
                  <Typography variant="h6" color="warning.main" gutterBottom>
                    Air Traffic Safety
                  </Typography>
                  <Typography variant="body2">
                    Supports air traffic control by managing unauthorized UAV intrusions.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          <Typography variant="h5" gutterBottom sx={{ mt: 4, borderBottom: '2px solid #4dabf5', pb: 1 }}>
            🛠️ How It Works
          </Typography>
          <Box sx={{ position: 'relative', mt: 3, mb: 4 }}>
            <Box sx={{
              display: 'flex',
              flexDirection: { xs: 'column', md: 'row' },
              gap: 3,
              position: 'relative',
              '&::before': {
                content: '""',
                position: 'absolute',
                top: '45px',
                left: { xs: '45px', md: '50%' },
                width: { xs: '2px', md: '80%' },
                height: { xs: '85%', md: '2px' },
                backgroundColor: '#4dabf5',
                transform: { xs: 'none', md: 'translateX(-50%)' },
                zIndex: 0
              }
            }}>
              <Card sx={{ flex: 1, zIndex: 1, position: 'relative' }}>
                <CardContent sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', p: 3 }}>
                  <Avatar sx={{ width: 60, height: 60, bgcolor: 'primary.main', mb: 2 }}>1</Avatar>
                  <Typography variant="h6" gutterBottom>Upload Media</Typography>
                  <Typography variant="body2">
                    Upload an image or video for analysis of potential drone activity
                  </Typography>
                </CardContent>
              </Card>

              <Card sx={{ flex: 1, zIndex: 1 }}>
                <CardContent sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', p: 3 }}>
                  <Avatar sx={{ width: 60, height: 60, bgcolor: 'primary.main', mb: 2 }}>2</Avatar>
                  <Typography variant="h6" gutterBottom>Processing</Typography>
                  <Typography variant="body2">
                    YOLOv8 model detects drones with adjustable confidence levels
                  </Typography>
                </CardContent>
              </Card>

              <Card sx={{ flex: 1, zIndex: 1 }}>
                <CardContent sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', p: 3 }}>
                  <Avatar sx={{ width: 60, height: 60, bgcolor: 'primary.main', mb: 2 }}>3</Avatar>
                  <Typography variant="h6" gutterBottom>Alert System</Typography>
                  <Typography variant="body2">
                    Automated email alerts sent when drones are detected
                  </Typography>
                </CardContent>
              </Card>

              <Card sx={{ flex: 1, zIndex: 1 }}>
                <CardContent sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', p: 3 }}>
                  <Avatar sx={{ width: 60, height: 60, bgcolor: 'primary.main', mb: 2 }}>4</Avatar>
                  <Typography variant="h6" gutterBottom>Detection Logs</Typography>
                  <Typography variant="body2">
                    Review historical detections for security analysis
                  </Typography>
                </CardContent>
              </Card>
            </Box>
          </Box>

          <Box sx={{ mt: 4, textAlign: 'center' }}>
            <Button
              variant="contained"
              size="large"
              component={Link}
              to="/image"
              startIcon={<CameraIcon />}
              sx={{
                px: 4,
                py: 1.5,
                background: 'linear-gradient(45deg, #1e3c72 30%, #4dabf5 90%)',
                boxShadow: '0 3px 5px 2px rgba(77, 171, 245, .3)',
              }}
            >
              Start Detecting Now
            </Button>
          </Box>
        </CardContent>
      </Card>
    </Container>
  );
}

// Image Detection Component with improved UI
function ImageDetection({ confidence, addToLog }) {
  const [selectedImage, setSelectedImage] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [alertSent, setAlertSent] = useState(false);
  const [error, setError] = useState(null);

  const handleImageUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      setSelectedFile(file);
      setSelectedImage(URL.createObjectURL(file));
      setResult(null);
      setAlertSent(false);
      setError(null);
    }
  };

  const detectDrones = async () => {
    if (!selectedFile) return;

    setLoading(true);
    setError(null);

    try {
      // Create FormData for file upload
      const formData = new FormData();
      formData.append('image', selectedFile);
      formData.append('confidence', confidence);

      const response = await fetch(`${API_BASE_URL}/api/detect-image`, {
        method: 'POST',
        body: formData, // Don't set Content-Type header, browser will set it with boundary
      });

      const data = await response.json();

      if (data.success) {
        // Properly handle the image URL from the server
        setResult(`${API_BASE_URL}${data.outputPath}`);
        setAlertSent(data.droneDetected);

        if (data.droneDetected) {
          addToLog(confidence);
        }
      } else {
        setError(data.error || 'An error occurred during detection');
        console.error(data.error);
      }
    } catch (error) {
      setError('Failed to connect to the server. Is the backend running?');
      console.error("Error detecting drones:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4 }}>
      <Card sx={{ mb: 4, overflow: 'hidden' }}>
        <Box sx={{ p: 0, position: 'relative' }}>
          <Box sx={{
            height: '120px',
            background: 'linear-gradient(90deg, #1e3c72 0%, #2a5298 100%)',
            display: 'flex',
            alignItems: 'flex-end',
            p: 3
          }}>
            <Typography variant="h5" sx={{ color: 'white', fontWeight: 'bold' }}>
              Image Detection
            </Typography>
          </Box>
        </Box>

        <CardContent sx={{ p: 4 }}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={5}>
              <Typography variant="body1" paragraph>
                Upload an image to detect drones using our advanced AI model. The system will analyze the image and identify any drones present.
              </Typography>

              <Paper elevation={0} sx={{ p: 3, mb: 3, borderRadius: 3, border: '1px dashed rgba(255,255,255,0.3)' }}>
                <Box sx={{ textAlign: 'center' }}>
                  <input
                    accept="image/*"
                    style={{ display: 'none' }}
                    id="upload-image-button"
                    type="file"
                    onChange={handleImageUpload}
                  />
                  <label htmlFor="upload-image-button">
                    <Box sx={{
                      border: '2px dashed rgba(77, 171, 245, 0.5)',
                      borderRadius: 2,
                      p: 3,
                      cursor: 'pointer',
                      transition: 'all 0.3s',
                      '&:hover': {
                        borderColor: '#4dabf5',
                        backgroundColor: 'rgba(77, 171, 245, 0.1)'
                      }
                    }}>
                      {selectedImage ? (
                        <Box
                          component="img"
                          src={selectedImage}
                          alt="Preview"
                          sx={{
                            maxWidth: '100%',
                            maxHeight: '150px',
                            display: 'block',
                            margin: '0 auto 16px'
                          }}
                        />
                      ) : (
                        <CameraIcon sx={{ fontSize: 60, color: 'primary.main', my: 2 }} />
                      )}

                      <Typography variant="body1" align="center" gutterBottom>
                        {selectedImage ? 'Change Image' : 'Select Image for Analysis'}
                      </Typography>
                      <Typography variant="body2" align="center" color="text.secondary">
                        Supports JPG, PNG, WEBP
                      </Typography>
                    </Box>
                  </label>
                </Box>

                <Box sx={{ mt: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography variant="body2">
                    Confidence: <strong>{confidence}</strong>
                  </Typography>

                  <Button
                    variant="contained"
                    color="primary"
                    onClick={detectDrones}
                    disabled={!selectedImage || loading}
                    startIcon={loading ? null : <SearchIcon />}
                    sx={{
                      px: 3,
                      background: 'linear-gradient(45deg, #1e3c72 30%, #4dabf5 90%)'
                    }}
                  >
                    {loading ? "Processing..." : "Detect Drones"}
                  </Button>
                </Box>
              </Paper>

              {error && (
                <Alert
                  severity="error"
                  variant="filled"
                  sx={{ mt: 2 }}
                >
                  {error}
                </Alert>
              )}

              {loading && (
                <Card sx={{ mt: 3, p: 3, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                    <CircularProgress size={40} color="primary" thickness={5} />
                    <Typography variant="subtitle1" sx={{ mt: 2 }}>
                      Processing Image...
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Analyzing using YOLOv8 model
                    </Typography>
                  </Box>
                </Card>
              )}
            </Grid>

            <Grid item xs={12} md={7}>
              {result && !loading && (
                <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                  <CardContent sx={{ flex: '1 0 auto', p: 3 }}>
                    <Typography variant="h6" gutterBottom>
                      Detection Results
                    </Typography>

                    <Box
                      component="img"
                      sx={{
                        width: '100%',
                        borderRadius: 2,
                        border: '1px solid #444',
                        mb: 2
                      }}
                      src={result}
                      alt="Detection Result"
                    />

                    {alertSent ? (
                      <Alert
                        severity="warning"
                        variant="filled"
                        sx={{ mt: 2 }}
                        action={
                          <IconButton color="inherit" size="small">
                            <SendIcon />
                          </IconButton>
                        }
                      >
                        🚨 Drone detected! Email alert sent!
                      </Alert>
                    ) : (
                      <Alert severity="success" variant="filled" sx={{ mt: 2 }}>
                        ✅ No drone detected in the image.
                      </Alert>
                    )}
                  </CardContent>
                </Card>
              )}

              {!result && !loading && (
                <Box sx={{
                  height: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'center',
                  alignItems: 'center',
                  backgroundColor: 'rgba(19, 47, 76, 0.4)',
                  borderRadius: 3,
                  p: 4
                }}>
                  <img
                    src="https://images.unsplash.com/photo-1473968512647-3e447244af8f?q=80&w=1740"
                    alt="Drone Detection"
                    style={{ maxWidth: '100%', maxHeight: '200px', borderRadius: '8px', marginBottom: '20px' }}
                  />
                  <Typography variant="h6" align="center" gutterBottom>
                    Upload an image to begin detection
                  </Typography>
                  <Typography variant="body2" align="center" color="text.secondary">
                    Our AI model will analyze your image and identify any drones present
                  </Typography>
                </Box>
              )}
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    </Container>
  );
}

// Video Detection Component with improved UI
function VideoDetection({ confidence, addToLog }) {
  const [selectedVideo, setSelectedVideo] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [processedVideo, setProcessedVideo] = useState(null);
  const [loading, setLoading] = useState(false);
  const [droneDetected, setDroneDetected] = useState(false);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState(0);

  // Mock progress update for better UX
  useEffect(() => {
    let interval;
    if (loading) {
      interval = setInterval(() => {
        setProgress((oldProgress) => {
          // Cap at 90% until actual completion
          const newProgress = Math.min(oldProgress + Math.random() * 5, 90);
          return newProgress;
        });
      }, 500);
    } else {
      setProgress(0);
    }
    return () => clearInterval(interval);
  }, [loading]);

  const handleVideoUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      setSelectedFile(file);
      setSelectedVideo(URL.createObjectURL(file));
      setProcessedVideo(null);
      setDroneDetected(false);
      setError(null);
    }
  };

  const processVideo = async () => {
    if (!selectedFile) return;

    setLoading(true);
    setError(null);

    try {
      // Create FormData for file upload
      const formData = new FormData();
      formData.append('video', selectedFile);
      formData.append('confidence', confidence);

      const response = await fetch(`${API_BASE_URL}/api/detect-video`, {
        method: 'POST',
        body: formData, // Don't set Content-Type header, browser will set it with boundary
      });

      const data = await response.json();

      if (data.success) {
        // Set progress to 100% when complete
        setProgress(100);
        // Properly handle the video URL from the server
        setProcessedVideo(`${API_BASE_URL}${data.outputPath}`);
        setDroneDetected(data.droneDetected);

        if (data.droneDetected) {
          addToLog(confidence);
        }
      } else {
        setError(data.error || 'An error occurred during processing');
        console.error(data.error);
      }
    } catch (error) {
      setError('Failed to connect to the server. Is the backend running?');
      console.error("Error processing video:", error);
    } finally {
      setLoading(false);
    }
  };

  const downloadProcessedVideo = () => {
    if (!processedVideo) return;

    const fileName = processedVideo.split('/').pop();
    const downloadUrl = `${API_BASE_URL}/download/${fileName}`;

    // Create a temporary anchor element
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.setAttribute('download', fileName);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4 }}>
      <Card sx={{ mb: 4, overflow: 'hidden' }}>
        <Box sx={{ p: 0, position: 'relative' }}>
          <Box sx={{
            height: '120px',
            background: 'linear-gradient(90deg, #1e3c72 0%, #2a5298 100%)',
            display: 'flex',
            alignItems: 'flex-end',
            p: 3
          }}>
            <Typography variant="h5" sx={{ color: 'white', fontWeight: 'bold' }}>
              Video Detection
            </Typography>
          </Box>
        </Box>

        <CardContent sx={{ p: 4 }}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={5}>
              <Typography variant="body1" paragraph>
                Upload a video to detect drones using our advanced AI model. The system will analyze each frame and identify any drones present.
              </Typography>

              <Paper elevation={0} sx={{ p: 3, mb: 3, borderRadius: 3, border: '1px dashed rgba(255,255,255,0.3)' }}>
                <Box sx={{ textAlign: 'center' }}>
                  <input
                    accept="video/*"
                    style={{ display: 'none' }}
                    id="upload-video-button"
                    type="file"
                    onChange={handleVideoUpload}
                  />
                  <label htmlFor="upload-video-button">
                    <Box sx={{
                      border: '2px dashed rgba(77, 171, 245, 0.5)',
                      borderRadius: 2,
                      p: 3,
                      cursor: 'pointer',
                      transition: 'all 0.3s',
                      '&:hover': {
                        borderColor: '#4dabf5',
                        backgroundColor: 'rgba(77, 171, 245, 0.1)'
                      }
                    }}>
                      {selectedVideo ? (
                        <Box
                          component="video"
                          controls
                          sx={{
                            maxWidth: '100%',
                            maxHeight: '150px',
                            display: 'block',
                            margin: '0 auto 16px'
                          }}
                          src={selectedVideo}
                        />
                      ) : (
                        <VideoIcon sx={{ fontSize: 60, color: 'primary.main', my: 2 }} />
                      )}

                      <Typography variant="body1" align="center" gutterBottom>
                        {selectedVideo ? 'Change Video' : 'Select Video for Analysis'}
                      </Typography>
                      <Typography variant="body2" align="center" color="text.secondary">
                        Supports MP4, MOV, AVI
                      </Typography>
                    </Box>
                  </label>
                </Box>

                <Box sx={{ mt: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography variant="body2">
                    Confidence: <strong>{confidence}</strong>
                  </Typography>

                  <Button
                    variant="contained"
                    color="primary"
                    onClick={processVideo}
                    disabled={!selectedVideo || loading}
                    startIcon={loading ? null : <SearchIcon />}
                    sx={{
                      px: 3,
                      background: 'linear-gradient(45deg, #1e3c72 30%, #4dabf5 90%)'
                    }}
                  >
                    {loading ? "Processing..." : "Process Video"}
                  </Button>
                </Box>
              </Paper>

              {error && (
                <Alert
                  severity="error"
                  variant="filled"
                  sx={{ mt: 2 }}
                >
                  {error}
                </Alert>
              )}

              {loading && (
                <Card sx={{ mt: 3, p: 3 }}>
                  <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                    <Box sx={{ position: 'relative', display: 'inline-flex', mb: 2 }}>
                      <CircularProgress variant="determinate" value={progress} size={60} thickness={5} />
                      <Box
                        sx={{
                          top: 0,
                          left: 0,
                          bottom: 0,
                          right: 0,
                          position: 'absolute',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}
                      >
                        <Typography variant="caption" color="text.secondary">{`${Math.round(progress)}%`}</Typography>
                      </Box>
                    </Box>
                    <Typography variant="subtitle1">
                      Processing Video...
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', mt: 1 }}>
                      This may take several minutes depending on the video length.
                      <br />
                      The AI is analyzing each frame using the YOLOv8 model.
                    </Typography>
                  </Box>
                </Card>
              )}
            </Grid>

            <Grid item xs={12} md={7}>
              {processedVideo && !loading && (
                <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                  <CardContent sx={{ flex: '1 0 auto', p: 3 }}>
                    <Typography variant="h6" gutterBottom>
                      Detection Results
                    </Typography>

                    <Box
                      component="video"
                      controls
                      sx={{
                        width: '100%',
                        borderRadius: 2,
                        border: '1px solid #444',
                        mb: 2
                      }}
                      src={processedVideo}
                    />

                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 2 }}>
                      <Button
                        variant="contained"
                        color="primary"
                        onClick={downloadProcessedVideo}
                        startIcon={<ArrowRightIcon />}
                        sx={{
                          background: 'linear-gradient(45deg, #1e3c72 30%, #4dabf5 90%)',
                        }}
                      >
                        Download Processed Video
                      </Button>

                      {droneDetected ? (
                        <Chip
                          icon={<SendIcon />}
                          label="Drone detected! Email alert sent!"
                          color="warning"
                          variant="filled"
                        />
                      ) : (
                        <Chip
                          icon={<CheckCircleIcon />}
                          label="No drone detected in the video"
                          color="success"
                          variant="filled"
                        />
                      )}
                    </Box>
                  </CardContent>
                </Card>
              )}

              {!processedVideo && !loading && (
                <Box sx={{
                  height: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'center',
                  alignItems: 'center',
                  backgroundColor: 'rgba(19, 47, 76, 0.4)',
                  borderRadius: 3,
                  p: 4
                }}>
                  <img
                    src="https://images.unsplash.com/photo-1473968512647-3e447244af8f?q=80&w=1740"
                    alt="Drone Video Detection"
                    style={{ maxWidth: '100%', maxHeight: '200px', borderRadius: '8px', marginBottom: '20px' }}
                  />
                  <Typography variant="h6" align="center" gutterBottom>
                    Upload a video to begin detection
                  </Typography>
                  <Typography variant="body2" align="center" color="text.secondary">
                    Our AI model will analyze each frame of your video and identify any drones present
                  </Typography>
                </Box>
              )}
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    </Container>
  );
}
// Logs Component
// Detection Logs Component with improved UI
function DetectionLogs({ logs, clearLogs }) {
  return (
    <Container maxWidth="lg" sx={{ mt: 4 }}>
      <Card sx={{ mb: 4, overflow: 'hidden' }}>
        <Box sx={{ p: 0, position: 'relative' }}>
          <Box sx={{
            height: '120px',
            background: 'linear-gradient(90deg, #1e3c72 0%, #2a5298 100%)',
            display: 'flex',
            alignItems: 'flex-end',
            p: 3
          }}>
            <Typography variant="h5" sx={{ color: 'white', fontWeight: 'bold' }}>
              Detection Logs
            </Typography>
          </Box>
        </Box>

        <CardContent sx={{ p: 4 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="body1">
              This page displays a history of all drone detections from both image and video processing.
            </Typography>

            <Button
              variant="contained"
              color="error"
              onClick={clearLogs}
              disabled={logs.length === 0}
              startIcon={<LogoutIcon />}
              sx={{
                px: 3,
                background: logs.length === 0 ? 'rgba(244, 67, 54, 0.5)' : 'linear-gradient(45deg, #d32f2f 30%, #f44336 90%)',
              }}
            >
              Clear All Logs
            </Button>
          </Box>

          {logs.length > 0 ? (
            <TableContainer component={Paper} sx={{ borderRadius: 2, boxShadow: 'none', border: '1px solid rgba(255, 255, 255, 0.12)' }}>
              <Table>
                <TableHead sx={{ backgroundColor: 'rgba(19, 47, 76, 0.4)' }}>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 'bold' }}>#</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Timestamp</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Confidence Threshold</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Alert Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {logs.map((log, index) => (
                    <TableRow key={index} sx={{
                      '&:nth-of-type(odd)': { backgroundColor: 'rgba(255, 255, 255, 0.03)' },
                      '&:hover': { backgroundColor: 'rgba(77, 171, 245, 0.08)' }
                    }}>
                      <TableCell>{index + 1}</TableCell>
                      <TableCell>{log.Timestamp}</TableCell>
                      <TableCell>{log.Confidence}</TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          icon={<SendIcon fontSize="small" />}
                          label="Alert Sent"
                          color="warning"
                          variant="outlined"
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Card sx={{
              p: 4,
              textAlign: 'center',
              backgroundColor: 'rgba(19, 47, 76, 0.4)',
              borderRadius: 3
            }}>
              <img
                src="https://images.unsplash.com/photo-1551288049-bebda4e38f71?q=80&w=1470"
                alt="No detection logs"
                style={{
                  height: '150px',
                  marginBottom: '20px',
                  borderRadius: '8px',
                  opacity: 0.8
                }}
              />
              <Typography variant="h6" gutterBottom>
                No Detection Logs Available
              </Typography>
              <Typography variant="body2" color="text.secondary">
                When drones are detected in your images or videos, they will appear here.
                <br />
                All detections automatically generate email alerts for security personnel.
              </Typography>
            </Card>
          )}
        </CardContent>
      </Card>
    </Container>
  );
}


// Main App Component with Authentication and 2FA
function App() {
  const [confidence, setConfidence] = useState(0.5);
  const [detectionLogs, setDetectionLogs] = useState([]);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);

  // Check for existing authentication on load
  useEffect(() => {
    const storedAuth = localStorage.getItem('isAuthenticated');
    const storedUser = localStorage.getItem('user');

    if (storedAuth === 'true' && storedUser) {
      setIsAuthenticated(true);
      setUser(JSON.parse(storedUser));
    }
  }, []);

  const handleConfidenceChange = (event, newValue) => {
    setConfidence(newValue);
  };

  const addToLog = (confidence) => {
    const timestamp = new Date().toLocaleString();
    setDetectionLogs([
      ...detectionLogs,
      {
        Timestamp: timestamp,
        Confidence: confidence
      }
    ]);
    sendEmailAlert(confidence);
  };

  const clearLogs = () => {
    setDetectionLogs([]);
  };

  const sendEmailAlert = (confidence) => {
    // In a real application, this would call a backend API that sends emails
    console.log(`Email alert sent for drone detection with confidence ${confidence}`);
    // This would be implemented as a backend API call
  };

  const handleLogout = () => {
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('user');
    setIsAuthenticated(false);
    setUser(null);
  };

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Router>
        {isAuthenticated ? (
          <Box sx={{ flexGrow: 1 }}>
            <AppBar position="static">
              <Toolbar>
                <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
                  Drone Detection System
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <Avatar
                    src={user?.avatar}
                    alt={user?.name}
                    sx={{ width: 32, height: 32, mr: 1 }}
                  />
                  <Typography variant="body1" sx={{ mr: 2 }}>
                    {user?.name}
                  </Typography>
                  <Button
                    color="inherit"
                    onClick={handleLogout}
                    startIcon={<LogoutIcon />}
                  >
                    Logout
                  </Button>
                </Box>
              </Toolbar>
            </AppBar>

            {/* Navigation and Settings */}
            <Container maxWidth="lg" sx={{ mt: 4 }}>
              <Box sx={{ display: 'flex', gap: 2 }}>
                {/* Settings Panel */}
                <Paper elevation={3} sx={{ p: 3, width: 240, position: 'sticky', top: 20 }}>
                  <Typography variant="h6" gutterBottom>
                    ⚙️ Settings
                  </Typography>

                  <Typography gutterBottom>Detection Confidence</Typography>
                  <Slider
                    value={confidence}
                    onChange={handleConfidenceChange}
                    min={0}
                    max={1}
                    step={0.05}
                    valueLabelDisplay="auto"
                    marks={[
                      { value: 0, label: '0' },
                      { value: 0.5, label: '0.5' },
                      { value: 1, label: '1' }
                    ]}
                  />

                  <Divider sx={{ my: 2 }} />

                  <Typography gutterBottom>Choose Mode</Typography>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    <Button
                      component={Link}
                      to="/"
                      startIcon={<InfoIcon />}
                      variant="outlined"
                      fullWidth
                    >
                      📌 Home
                    </Button>
                    <Button
                      component={Link}
                      to="/image"
                      startIcon={<CameraIcon />}
                      variant="outlined"
                      fullWidth
                    >
                      📷 Image Detection
                    </Button>
                    <Button
                      component={Link}
                      to="/video"
                      startIcon={<VideoIcon />}
                      variant="outlined"
                      fullWidth
                    >
                      🎥 Video Detection
                    </Button>
                    <Button
                      component={Link}
                      to="/logs"
                      startIcon={<ListIcon />}
                      variant="outlined"
                      fullWidth
                    >
                      📜 View Logs
                    </Button>
                  </Box>
                </Paper>

                {/* Main Content */}
                <Box sx={{ flexGrow: 1 }}>
                  <Routes>
                    <Route path="/" element={<About />} />
                    <Route
                      path="/image"
                      element={<ImageDetection confidence={confidence} addToLog={addToLog} />}
                    />
                    <Route
                      path="/video"
                      element={<VideoDetection confidence={confidence} addToLog={addToLog} />}
                    />
                    <Route
                      path="/logs"
                      element={<DetectionLogs logs={detectionLogs} clearLogs={clearLogs} />}
                    />
                  </Routes>
                </Box>
              </Box>
            </Container>
          </Box>
        ) : (
          <Routes>
            <Route path="*" element={<Login setIsAuthenticated={setIsAuthenticated} setUser={setUser} />} />
          </Routes>
        )}
      </Router>
    </ThemeProvider>
  );
}
export default App;
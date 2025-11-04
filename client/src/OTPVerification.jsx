import React, { useState, useEffect, useRef } from 'react';
import {
    Box,
    Typography,
    TextField,
    Button,
    CircularProgress,
    Alert,
    Stack
} from '@mui/material';
import axios from 'axios';

function OTPVerification({ username, onSuccess, onCancel }) {
    const [otp, setOtp] = useState(['', '', '', '', '', '']);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [countdown, setCountdown] = useState(0);
    const [expiresAt, setExpiresAt] = useState(null);
    const inputRefs = useRef([]);

    // Request OTP when component mounts
    useEffect(() => {
        requestOTP();
    }, []);

    // Handle countdown timer
    useEffect(() => {
        let timer;
        if (expiresAt) {
            timer = setInterval(() => {
                const remainingTime = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
                setCountdown(remainingTime);

                if (remainingTime <= 0) {
                    clearInterval(timer);
                }
            }, 1000);
        }

        return () => {
            if (timer) clearInterval(timer);
        };
    }, [expiresAt]);

    const requestOTP = async () => {
        setIsLoading(true);
        setError('');
        try {
            const response = await axios.post('/api/request-otp', { username });
            if (response.data.success) {
                setSuccess('OTP sent successfully! Check your email.');
                setExpiresAt(response.data.expiresAt);
            } else {
                setError(response.data.error || 'Failed to send OTP');
            }
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to request OTP. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    const verifyOTP = async () => {
        const otpValue = otp.join('');
        if (otpValue.length !== 6) {
            setError('Please enter all 6 digits');
            return;
        }

        setIsLoading(true);
        setError('');
        try {
            const response = await axios.post('/api/verify-otp', {
                username,
                otp: otpValue
            });

            if (response.data.success) {
                setSuccess('OTP verified successfully!');
                setTimeout(() => {
                    onSuccess(response.data.token);
                }, 1000);
            } else {
                setError(response.data.error || 'Failed to verify OTP');
            }
        } catch (err) {
            setError(err.response?.data?.error || 'Invalid OTP. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    const handleChange = (index, value) => {
        // Only allow digits
        if (value && !/^\d*$/.test(value)) return;

        const newOtp = [...otp];
        newOtp[index] = value;
        setOtp(newOtp);

        // Auto-focus to next input
        if (value && index < 5) {
            inputRefs.current[index + 1].focus();
        }
    };

    const handleKeyDown = (index, e) => {
        // Move to previous input on backspace
        if (e.key === 'Backspace' && !otp[index] && index > 0) {
            inputRefs.current[index - 1].focus();
        }
    };

    const formatTime = (seconds) => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    };

    return (
        <Box sx={{ textAlign: 'center' }}>
            <Typography variant="h5" component="h2" sx={{ mb: 2, color: '#fff', fontWeight: 'bold' }}>
                Two-Factor Authentication
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, color: '#bbb' }}>
                Enter the 6-digit code sent to your email
            </Typography>

            <Box sx={{ mb: 4 }}>
                <Stack direction="row" spacing={1} justifyContent="center">
                    {otp.map((digit, index) => (
                        <TextField
                            key={index}
                            inputRef={el => inputRefs.current[index] = el}
                            variant="outlined"
                            value={digit}
                            onChange={(e) => handleChange(index, e.target.value)}
                            onKeyDown={(e) => handleKeyDown(index, e)}
                            inputProps={{
                                maxLength: 1,
                                style: {
                                    textAlign: 'center',
                                    fontSize: '1.5rem',
                                    padding: '10px',
                                    width: '40px',
                                    height: '40px'
                                }
                            }}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: 'rgba(255, 255, 255, 0.3)',
                                    },
                                    '&:hover fieldset': {
                                        borderColor: 'rgba(255, 255, 255, 0.5)',
                                    },
                                    '&.Mui-focused fieldset': {
                                        borderColor: '#4dabf5',
                                    }
                                }
                            }}
                        />
                    ))}
                </Stack>
            </Box>

            {countdown > 0 && (
                <Typography variant="body2" sx={{ mb: 2, color: '#bbb' }}>
                    Code expires in: {formatTime(countdown)}
                </Typography>
            )}

            {error && (
                <Alert severity="error" sx={{ mb: 2 }}>
                    {error}
                </Alert>
            )}

            {success && (
                <Alert severity="success" sx={{ mb: 2 }}>
                    {success}
                </Alert>
            )}

            <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
                <Button
                    variant="outlined"
                    onClick={onCancel}
                    sx={{ color: '#fff', borderColor: 'rgba(255, 255, 255, 0.3)' }}
                >
                    Back
                </Button>

                <Button
                    variant="outlined"
                    onClick={requestOTP}
                    disabled={isLoading || countdown > 0}
                    sx={{ color: '#fff', borderColor: 'rgba(255, 255, 255, 0.3)' }}
                >
                    Resend OTP {countdown > 0 && `(${formatTime(countdown)})`}
                </Button>

                <Button
                    variant="contained"
                    onClick={verifyOTP}
                    disabled={isLoading || otp.join('').length !== 6}
                    sx={{
                        background: 'linear-gradient(90deg, #1e3c72 0%, #2a5298 100%)',
                        '&:hover': {
                            background: 'linear-gradient(90deg, #2a5298 0%, #1e3c72 100%)',
                        }
                    }}
                >
                    {isLoading ? <CircularProgress size={24} color="inherit" /> : "Verify"}
                </Button>
            </Box>
        </Box>
    );
}

export default OTPVerification;
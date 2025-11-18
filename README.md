# Drone Detection & Intrusion Prevention System

An intelligent web-based system for **real-time drone detection** and **network intrusion prevention**, powered by **YOLOv8, CNN/ResNet, and Random Forest–based NIDS**. :contentReference[oaicite:0]{index=0}  

🔗 **Live Demo:** https://drone-detection-app-1.onrender.com  

---

## 📌 Overview

The system is designed to secure restricted airspaces (critical infrastructure, military zones, border areas, etc.) from **unauthorized drones** and **cyber attacks**. It combines:

- **Computer vision** (YOLOv8 + ResNet) for detecting and classifying drones in images/videos.
- **Network Intrusion Detection System (NIDS)** using Random Forest to detect attacks like DoS, Probe, R2L, and U2R.
- A **modern dashboard** that lets security operators:
  - Upload images/videos
  - Adjust detection confidence
  - View logs
  - Receive alerts

---

## ✨ Key Features

### Frontend & User Experience
- 🎛 **Detection Confidence Slider** – Fine-tune model sensitivity between 0–1.
- 🏠 **Home Dashboard**
  - Project overview and quick links
  - Cards for Image/Video Detection, Adjustable Confidence, and Email Alerts
- 🖼 **Image Detection**
  - Upload single images to detect drones.
  - Bounding boxes and labels overlaid on the image.
- 🎥 **Video Detection**
  - Upload videos for frame-by-frame drone detection.
  - Supports real-time and recorded surveillance feeds.
- 📜 **View Logs**
  - History of detections with timestamps, confidence scores, and file names.
- 📧 **Email Alerts (Conceptual / Optional)**
  - Immediate notifications when an unauthorized drone is detected over a threshold.

### Backend & Intelligence
- 🧠 **YOLOv8 Object Detection**
  - Detects and localizes drones in images and video streams.
- 🧩 **CNN + ResNet50**
  - Refines classification and reduces false positives (e.g., differentiating drones from birds/planes).
- 🛡 **Network Intrusion Detection (NIDS)**
  - Random Forest model trained on NSL-KDD (or similar) dataset.
  - Detects threats such as:
    - DoS (Denial of Service)
    - Probe & Scanning
    - Remote to Local (R2L)
    - User to Root (U2R)
  - Mitigation strategies (design level):
    - Rate limiting & traffic filtering
    - IP blocking / access control
    - Session monitoring & termination
    - OTP verification for sensitive actions
    - XSS prevention

---

## 🧱 System Architecture (High-Level)

1. **User Interface (Web App)**
   - Built as a responsive dashboard.
   - Routes: `Home`, `Image Detection`, `Video Detection`, `View Logs`.

2. **Drone Detection Service**
   - Accepts image/video uploads.
   - Runs YOLOv8 for object detection.
   - Passes cropped regions to CNN/ResNet for fine-grained classification.
   - Returns predictions (labels, confidence, bounding boxes) to the UI.

3. **NIDS Service**
   - Monitors network traffic features.
   - Uses a Random Forest model to classify normal vs. attack traffic.
   - Triggers alerts and prevention actions.

4. **Database / Storage**
   - Stores:
     - Detection logs
     - Uploaded media metadata
     - NIDS alerts
     - User activity traces (optional).

5. **Notification Layer (Optional)**
   - Email / webhook notifications for critical events.

---

## 🛠 Tech Stack

> Adapt as needed to match your actual repo structure.

- **Frontend**
  - React / Next.js (or any modern JS framework)
  - HTML5, CSS3 / Tailwind / Styled Components
- **Backend**
  - Python (FastAPI / Flask / Django REST Framework)
  - OpenCV for image/video handling
  - PyTorch / Ultralytics for YOLOv8
  - scikit-learn for Random Forest & evaluation
- **Models**
  - YOLOv8 for object detection
  - ResNet50 (pretrained) as feature extractor
  - Random Forest for intrusion detection
- **Deployment**
  - Render for web hosting (`onrender.com`)
  - Optional: GPU-enabled environment for heavy inference

---

## 📊 Dataset & Model Details

### Drone Detection
- **Dataset size:** 6,000+ images (~1.5 GB) of drones in varied conditions  
- **Preprocessing:**
  - Image–label pairing with bounding-box annotations
  - Data augmentation for lighting, angle, and background variations
- **Model:**
  - YOLOv8 trained with transfer learning
  - ResNet50 used to extract deep features from detected crops and refine classification

### Network Intrusion Detection
- **Dataset:** NSL-KDD (or similar intrusion dataset)
- **Model:** Random Forest
  - Trained to detect multiple attack classes
  - Uses majority voting across decision trees

---

## ✅ Results (Summary)

- **Drone Detection**
  - Final training accuracy: **~98%**
  - Validation accuracy: **~92%**
  - Real-time performance: **up to ~31.2 FPS** (≈31.2 ms per frame)
  - Outperforms baseline YOLOv5 setups (reported ~94.1% mAP) by integrating YOLOv8 + ResNet and better augmentation.

- **Intrusion Detection**
  - High accuracy on detecting DoS, Probe, R2L, and U2R classes (exact metrics depend on final training run).
  - Reduced false positives through feature engineering and tuned thresholds.

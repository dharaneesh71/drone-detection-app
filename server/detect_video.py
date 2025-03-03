# detect_video.py
import argparse
import cv2
import os
from ultralytics import YOLO
import time

def main():
    parser = argparse.ArgumentParser(description='Detect drones in a video using YOLOv8')
    parser.add_argument('--input', type=str, required=True, help='Path to input video')
    parser.add_argument('--output', type=str, required=True, help='Path to output detected video')
    parser.add_argument('--confidence', type=float, default=0.5, help='Detection confidence threshold')
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not os.path.isfile(args.input):
        print(f"Error: Input file {args.input} does not exist.")
        return False
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    
    # Load YOLO model
    model = YOLO('best.pt')  # Path to your trained model
    
    # Open the video file
    cap = cv2.VideoCapture(args.input)
    if not cap.isOpened():
        print(f"Error: Could not open video file {args.input}")
        return False
    
    # Get video properties
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = int(cap.get(cv2.CAP_PROP_FPS))
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    
    # Initialize video writer
    # Use H.264 codec with MP4 container
    fourcc = cv2.VideoWriter_fourcc(*'avc1')  # or 'H264'
    out = cv2.VideoWriter(args.output, fourcc, fps, (width, height))
    
    # Process the video
    frame_count = 0
    drone_detected = False
    start_time = time.time()
    
    print(f"Processing video with {total_frames} frames...")
    
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        
        # Process frame
        results = model.predict(frame, conf=args.confidence)
        annotated_frame = results[0].plot()
        
        # Write to output video
        out.write(annotated_frame)
        
        # Check for drone detections
        if len(results[0].boxes) > 0:
            drone_detected = True
        
        # Progress update (every 10% or 30 frames)
        frame_count += 1
        if frame_count % max(30, total_frames // 10) == 0:
            progress = frame_count / total_frames * 100
            elapsed = time.time() - start_time
            fps_processing = frame_count / elapsed
            eta = (total_frames - frame_count) / fps_processing if fps_processing > 0 else 0
            print(f"Progress: {progress:.1f}% ({frame_count}/{total_frames}), ETA: {eta:.1f}s")
    
    # Release resources
    cap.release()
    out.release()
    
    print(f"Video processing complete. Output saved to {args.output}")
    print(f"Drone detected: {drone_detected}")
    
    return drone_detected

if __name__ == "__main__":
    main()
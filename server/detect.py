# detect.py
import argparse
import cv2
import os
from ultralytics import YOLO

def main():
    parser = argparse.ArgumentParser(description='Detect drones in an image using YOLOv8')
    parser.add_argument('--input', type=str, required=True, help='Path to input image')
    parser.add_argument('--output', type=str, required=True, help='Path to output detected image')
    parser.add_argument('--confidence', type=float, default=0.5, help='Detection confidence threshold')
    
    args = parser.parse_args()
    
    # Load YOLO model
    model = YOLO('best.pt')  # Path to your trained model
    
    # Read image
    img = cv2.imread(args.input)
    if img is None:
        print(f"Error: Could not read image from {args.input}")
        return False
    
    # Perform detection
    results = model.predict(img, conf=args.confidence)
    
    # Draw the detection results
    detection_img = results[0].plot()
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    
    # Save output image
    cv2.imwrite(args.output, detection_img)
    
    # Return number of detections for analysis
    num_detections = len(results[0].boxes)
    print(f"Found {num_detections} drone(s) in the image.")
    
    return num_detections > 0

if __name__ == "__main__":
    main()
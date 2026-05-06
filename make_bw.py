import cv2
import numpy as np

def main():
    input_path = r'C:\Users\rishe\OneDrive\Desktop\Honeypot\report_images_light\architecture.png'
    output_path = r'C:\Users\rishe\OneDrive\Desktop\Honeypot\report_images_light\architecture_bw.png'
    
    img = cv2.imread(input_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        print("Could not read image")
        return

    # If image has alpha channel, composite it onto a black background
    if img.shape[2] == 4:
        alpha = img[:,:,3].astype(float) / 255.0
        bg = np.zeros_like(img[:,:,:3])
        for c in range(3):
            bg[:,:,c] = img[:,:,c] * alpha
        gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    else:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # We want to extract text and borders (which are brighter than their surroundings).
    # adaptiveThreshold with a negative C will set pixels to 255 if they are significantly brighter than local mean.
    # blockSize must be odd. 15 is a good start.
    edges = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 21, -5)
    
    # Invert the edges so we get black lines on white background
    bw = cv2.bitwise_not(edges)
    
    # Let's apply a slight morphological operation to clean up noise if needed, but for now just save it.
    cv2.imwrite(output_path, bw)
    print(f"Saved BW image to {output_path}")

if __name__ == "__main__":
    main()

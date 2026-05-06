import cv2
import numpy as np

def main():
    input_path = r'C:\Users\rishe\OneDrive\Desktop\Honeypot\report_images_light\architecture.png'
    output_path = r'C:\Users\rishe\OneDrive\Desktop\Honeypot\report_images_light\architecture_bw_final.png'
    
    img = cv2.imread(input_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        print("Could not read image")
        return

    # Put on black background to handle transparency
    if img.shape[2] == 4:
        alpha = img[:,:,3].astype(float) / 255.0
        bg = np.zeros_like(img[:,:,:3])
        for c in range(3):
            bg[:,:,c] = img[:,:,c] * alpha
        # bg now has white text/borders on black background, with some colored fills.
    else:
        bg = img

    # Invert the image.
    # Now we have black text/borders on a white background, with colored fills being medium-light.
    inv = cv2.bitwise_not(bg)
    gray = cv2.cvtColor(inv, cv2.COLOR_BGR2GRAY)

    # Adaptive thresholding.
    # A pixel becomes 255 (white) if gray(x,y) > local_mean - C.
    # Otherwise it becomes 0 (black).
    # Since text is black (0) and fills are medium-light (e.g. 150),
    # text will be < local_mean - C, so it becomes 0.
    # Uniform fills will be == local_mean, which is > local_mean - C, so they become 255.
    # This perfectly extracts local dark features (the text and borders) into black, and makes fills white!
    bw = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 15)
    
    # Save the output
    cv2.imwrite(output_path, bw)
    print(f"Saved optimized BW image to {output_path}")

if __name__ == "__main__":
    main()

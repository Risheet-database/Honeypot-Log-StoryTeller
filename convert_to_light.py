import sys
from PIL import Image
import colorsys

def invert_lightness(r, g, b):
    # Convert RGB to HLS (Hue, Lightness, Saturation)
    h, l, s = colorsys.rgb_to_hls(r / 255.0, g / 255.0, b / 255.0)
    # Invert lightness
    l = 1.0 - l
    # Convert back to RGB
    r_new, g_new, b_new = colorsys.hls_to_rgb(h, l, s)
    return int(r_new * 255), int(g_new * 255), int(b_new * 255)

def main():
    input_path = r'C:\Users\rishe\OneDrive\Desktop\Honeypot\report_images_light\architecture.png'
    output_path = r'C:\Users\rishe\OneDrive\Desktop\Honeypot\report_images_light\architecture_light_theme.png'
    
    img = Image.open(input_path).convert("RGBA")
    data = img.getdata()
    
    new_data = []
    for item in data:
        r, g, b, a = item
        # If the pixel is transparent or mostly transparent, we treat it as background (white in light theme)
        if a < 128:
            new_data.append((255, 255, 255, 255))
        else:
            # Invert the lightness of the pixel
            r_new, g_new, b_new = invert_lightness(r, g, b)
            new_data.append((r_new, g_new, b_new, 255))
            
    img.putdata(new_data)
    img.save(output_path)
    print(f"Successfully saved light-theme version to {output_path}")

if __name__ == "__main__":
    main()

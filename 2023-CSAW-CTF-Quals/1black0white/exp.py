raw = [533258111,274428993,391005533,391777629,390435677,273999169,534074751,99072,528317354,446173689,485174588,490627992,105525542,421383123,132446300,431853817,534345998,496243321,365115424,302404521,289808374,1437979,534308692,272742168,391735804,391385911,391848254,273838450,534645340]
print(len(raw))
res = ''
for x in raw:
    rrr = bin(x)[2:].rjust(29,'0')
    res+=rrr
    print(rrr)
print(len(res))

from PIL import Image

def generate_image_from_binary(binary_string):
    # Determine the width and height of the image
    width = len(binary_string)
    width = 29
    height = 29  # 4x8 pixels
    # Create a new image with the determined width and height
    img = Image.new("RGB", (width, height))

    # Iterate over the binary string and set pixel colors
    for i, char in enumerate(binary_string):
        x = i % width
        y = i // width
        color = (255, 255, 255) if char == "0" else (0, 0, 0)
        img.putpixel((x, y), color)

    return img

img = generate_image_from_binary(res)
img.save("test.png")
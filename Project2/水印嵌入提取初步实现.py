from PIL import Image, ImageEnhance
import random


# 填充二进制为8位
def plus(str):
    return str.zfill(8)


# 获取水印图片的每一个像素值
def getcode(watermark):
    str1 = ""
    for i in range(watermark.size[0]):
        for j in range(watermark.size[1]):
            # 获取每个像素的RGB值
            rgb = watermark.getpixel((i, j))
            str1 += plus(bin(rgb[0]).replace('0b', ''))
            str1 += plus(bin(rgb[1]).replace('0b', ''))
            str1 += plus(bin(rgb[2]).replace('0b', ''))
    return str1


# 加密
def encry(img, code):
    count = 0
    codelen = len(code)
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            # 获取每个像素的RGB值
            data = img.getpixel((i, j))
            if count == codelen:
                break
            r = data[0]
            g = data[1]
            b = data[2]
            # 替换每个像素的最低位
            r = (r - r % 2) + int(code[count])
            count += 1
            if count == codelen:
                img.putpixel((i, j), (r, g, b))
                break
            g = (g - g % 2) + int(code[count])
            count += 1
            if count == codelen:
                img.putpixel((i, j), (r, g, b))
                break
            b = (b - b % 2) + int(code[count])
            count += 1
            if count == codelen:
                img.putpixel((i, j), (r, g, b))
                break
            if count % 3 == 0:
                img.putpixel((i, j), (r, g, b))
    img.save('result.png')


# 解密
def deEncry(img, length):
    width = img.size[0]
    height = img.size[1]
    count = 0
    wt = ""

    for i in range(width):
        for j in range(height):
            # 获取像素点的值
            rgb = img.getpixel((i, j))
            if count % 3 == 0:
                count += 1
                wt = wt + str(rgb[0] % 2)
            if count % 3 == 1:
                count += 1
                wt = wt + str(rgb[1] % 2)
            if count % 3 == 2:
                count += 1
                wt = wt + str(rgb[2] % 2)
            if count == length:
                break
        if count == length:
            break
    return wt


# 显示水印
def showImage(wt, width, height):
    str2 = []
    # 将二进制转换为十进制的RGB
    for i in range(0, len(wt), 8):
        str2.append(int(wt[i:i + 8], 2))

    img_out = Image.new("RGB", (width, height))
    flag = 0
    for m in range(0, width):
        for n in range(0, height):
            img_out.putpixel((m, n), (str2[flag], str2[flag + 1], str2[flag + 2]))
            flag += 3
    img_out.show()




# 测试代码
if __name__ == "__main__":
    im = Image.open("example.png")
    watermark = Image.open("watermark.png")
    watermark = watermark.convert("RGB")

    # 获取水印编码
    code = getcode(watermark)

    # 水印嵌入
    encry(im, code)

    # 加载水印嵌入后的图片
    img1 = Image.open("result.png")
    rgb_img1 = img1.convert('RGB')

    # 解密并显示水印
    length = 90576  # 水印图片的像素点数，或者可以通过水印图片的实际大小来确定
    wt = deEncry(rgb_img1, length)

    # 显示提取的水印
    showImage(wt, watermark.size[0], watermark.size[1])


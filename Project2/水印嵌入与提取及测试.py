import cv2
import numpy as np


def lsb_insert(host_img, mark_img):

    mark_resized = cv2.resize(mark_img, (host_img.shape[1], host_img.shape[0]))
    # 转换为0/1二值
    mark_bin = (mark_resized > 127).astype(np.uint8)

    merged_img = host_img.copy()
    merged_img = (merged_img & 0b11111110) | mark_bin

    return merged_img


def lsb_extract(img_with_mark):

    return img_with_mark & 1


def evaluate_resilience(img_with_mark, orig_mark):

    ops = {
        "水平翻转": lambda x: cv2.flip(x, 1),
        "平移": lambda x: cv2.warpAffine(x, np.float32([[1, 0, 30], [0, 1, 30]]),
                                       (x.shape[1], x.shape[0])),
        "旋转90度": lambda x: cv2.rotate(x, cv2.ROTATE_90_CLOCKWISE),
        "缩小一半": lambda x: cv2.resize(x, (x.shape[1] // 2, x.shape[0] // 2)),
        "增加对比度": lambda x: cv2.convertScaleAbs(x, alpha=1.4, beta=0)
    }

    for op_name, func in ops.items():
        transformed = func(img_with_mark)
        extracted = lsb_extract(transformed)
        similarity = np.mean(extracted == (orig_mark > 127).astype(np.uint8))
        print(f"{op_name} 处理后相似度: {similarity * 100:.2f}%")


if __name__ == "__main__":
    # 读取灰度图
    host = cv2.imread("original_image.jpg", cv2.IMREAD_GRAYSCALE)
    mark = cv2.imread("watermark.jpg", cv2.IMREAD_GRAYSCALE)

    if host is None or mark is None:
        print("请确保 original_image.jpg 和 watermark.jpg 存在并放在代码目录下")
        exit()

    # 嵌入水印
    watermarked = lsb_insert(host, mark)
    cv2.imwrite("watermarked.jpg", watermarked)
    print("水印已嵌入并保存为 watermarked.jpg")

    # 提取水印
    recovered_mark = lsb_extract(watermarked) * 255
    cv2.imwrite("extracted_watermark.jpg", recovered_mark)
    print("提取的水印已保存为 extracted_watermark.jpg")

    # 测试鲁棒性
    print("\n开始鲁棒性测试：")
    evaluate_resilience(watermarked, mark)

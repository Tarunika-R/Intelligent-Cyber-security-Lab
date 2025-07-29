import math


def compute_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        entropy = 0.0
        for count in byte_counts:
            if count == 0:
                continue
            p = count / len(data)
            entropy -= p * math.log2(p)
        return round(entropy, 2)
    except:
        return 0.0

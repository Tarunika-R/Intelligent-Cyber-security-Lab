import csv
import random


def generate_entropy(label):
    if label == "Benign":
        eb = round(random.uniform(2.5, 4.5), 2)
        ea = round(eb + random.uniform(-0.3, 0.3), 2)
    else:
        eb = round(random.uniform(2.0, 4.0), 2)
        ea = round(random.uniform(7.0, 8.0), 2)
    return eb, ea


def generate_renamed(label):
    return "Yes" if label == "Ransomware" and random.random() > 0.2 else "No"


def generate_time_diff(label):
    if label == "Benign":
        return f"{random.randint(10, 60)} sec"
    else:
        return f"{random.randint(1, 9)} sec"


def generate_dataset(num_samples=100):
    rows = []
    for i in range(num_samples):
        label = "Ransomware" if i < num_samples // 2 else "Benign"
        eb, ea = generate_entropy(label)
        renamed = generate_renamed(label)
        size_kb = round(random.uniform(5, 500), 1)
        time_diff = generate_time_diff(label)
        rows.append([eb, ea, renamed, size_kb, time_diff, label])
    return rows


# Save to CSV
with open("ransomware_dataset.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(
        [
            "Entropy_Before",
            "Entropy_After",
            "Renamed",
            "Size (KB)",
            "Time_Between_Actions",
            "Label",
        ]
    )
    writer.writerows(generate_dataset(100))

print("✅ Dataset saved as 'ransomware_dataset.csv' (without Filename column)")

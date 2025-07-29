import os
import time
import joblib
import pandas as pd
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils import compute_entropy  # Make sure this is in utils.py

# Load trained ML model
model = joblib.load(
    r"D:\TARU\V th year\Intelligent Cyber security Lab\ex8\ransomware_detector_model.pkl"
)
print("✅ Loaded ML model.")

# Directory to monitor
WATCH_DIR = r"D:\TARU\V th year\Intelligent Cyber security Lab\ex8\output_pdfs"
os.makedirs(WATCH_DIR, exist_ok=True)

# Store previous file info
file_state = {}
rename_log = deque(maxlen=20)  # store recent rename timestamps


class MonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            handle_event(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            handle_event(event.src_path, "modified")

    def on_moved(self, event):
        if not event.is_directory:
            rename_log.append(time.time())
            handle_event(event.dest_path, "renamed")


def extract_features(path, event_type):
    try:
        entropy_now = compute_entropy(path)
        size_kb = os.path.getsize(path) / 1024
        now = time.time()

        if path not in file_state:
            file_state[path] = {"entropy": entropy_now, "time": now, "size": size_kb}
            return [
                entropy_now,
                entropy_now,
                int(event_type == "renamed"),
                size_kb,
                0.0,
            ]

        prev = file_state[path]
        time_diff = now - prev["time"]
        entropy_before = prev["entropy"]

        file_state[path] = {"entropy": entropy_now, "time": now, "size": size_kb}

        return [
            entropy_before,
            entropy_now,
            int(event_type == "renamed"),
            size_kb,
            round(time_diff, 2),
        ]
    except Exception as e:
        print(f"[ERROR] Failed to extract features from {path}: {e}")
        return None


def is_mass_renaming(threshold=5, interval=10):
    now = time.time()
    recent = [t for t in rename_log if now - t <= interval]
    return len(recent) >= threshold


def handle_event(path, event_type):
    features = extract_features(path, event_type)
    if features is None:
        return

    feature_names = [
        "Entropy_Before",
        "Entropy_After",
        "Renamed",
        "Size (KB)",
        "Time_Between_Actions",
    ]
    features_df = pd.DataFrame([features], columns=feature_names)
    prediction = model.predict(features_df)[0]

    mass_rename = is_mass_renaming()

    if prediction == 1 or mass_rename:
        print(f"\n🚨 RANSOMWARE DETECTED! Suspicious file: {path}")
        print(
            f"📊 Features: EntropyBefore={features[0]}, EntropyAfter={features[1]}, Renamed={features[2]}, Size={features[3]} KB, TimeDiff={features[4]} sec"
        )
        if mass_rename:
            print("⚠️ Mass renaming pattern detected! (>5 files in 10 sec)")
    else:
        print(f"✅ Benign activity: {os.path.basename(path)}")


if __name__ == "__main__":
    observer = Observer()
    handler = MonitorHandler()
    observer.schedule(handler, path=WATCH_DIR, recursive=True)
    observer.start()
    print(f"🔍 Monitoring directory: {WATCH_DIR} for ransomware activity...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("🛑 Stopped monitoring.")
    observer.join()

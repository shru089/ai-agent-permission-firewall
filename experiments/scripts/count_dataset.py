import json
with open("revision/data/dataset_v1.json", "r") as f:
    data = json.load(f)
print(f"dataset_v1.json size: {len(data)} samples")

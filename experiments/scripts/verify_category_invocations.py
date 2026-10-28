import pandas as pd
import json

RESULTS_DIR = "revision/results"
DATASET_PATH = "revision/data/expanded_dataset.json"

# Load dataset to get attack categories
with open(DATASET_PATH, 'r') as f:
    dataset = json.load(f)

# Create a mapping of sample_id -> category
id_to_cat = {s['sample_id']: s.get('attack_category', 'none') for s in dataset}
id_to_label = {s['sample_id']: s.get('label', 'benign') for s in dataset}

# Load FullCascade logs
df = pd.read_csv(f"{RESULTS_DIR}/logs_FullCascade.csv")

# 1. Verify Deep Invocations by Category
deep_invocations = df[df['t3_invoked'] == True]
deep_ids = set(deep_invocations['sample_id'])

# Count by category
cat_counts = {}
for aid in deep_ids:
    cat = id_to_cat.get(aid, 'unknown')
    cat_counts[cat] = cat_counts.get(cat, 0) + 1

print("--- Deep Invocation Counts by Category (FullCascade) ---")
for cat, count in cat_counts.items():
    print(f"{cat}: {count}")

# 2. Verify Benign Deep Invocations
benign_ids = [s['sample_id'] for s in dataset if s.get('label') == 'benign']
benign_deep_count = len([aid for aid in benign_ids if aid in deep_ids])
print(f"\nBenign Deep Invocations: {benign_deep_count}")

# 3. Cross-check with Total
print(f"Total Deep Invocations (from log): {df['t3_invoked'].sum()}")
print(f"Sum of Category counts: {sum(cat_counts.values())}")

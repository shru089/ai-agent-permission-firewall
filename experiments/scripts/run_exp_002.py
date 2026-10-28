import json
import os
from revision.src.run_benchmark_stable import run_strategy

# New output directory
RESULTS_DIR = "revision/results/exp_002"
os.makedirs(RESULTS_DIR, exist_ok=True)

# Override RESULTS_ROOT in the module to use the new directory
import revision.src.run_benchmark_stable
revision.src.run_benchmark_stable.RESULTS_ROOT = RESULTS_DIR

DATASET_PATH = "revision/data/pilot_dataset_mini.json"
with open(DATASET_PATH, 'r') as f:
    dataset = json.load(f)

# Run only FullCascade for exp_002
run_strategy("FullCascade", dataset, experiment_id="exp_002", repetition=0)

print(f"\nExperiment exp_002 completed. Logs saved to {RESULTS_DIR}")

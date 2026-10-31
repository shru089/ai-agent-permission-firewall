import pandas as pd
import json

RESULTS_DIR = "revision/results"
DATASET_PATH = "revision/data/expanded_dataset.json"

with open(DATASET_PATH, 'r') as f:
    dataset = json.load(f)
id_to_label = {s['sample_id']: s.get('label', 'benign') for s in dataset}

def audit_strat(strat_name):
    df = pd.read_csv(f"{RESULTS_DIR}/logs_{strat_name}.csv")
    
    # We want a cross-tab of T2 parsed verdict vs terminal route and final action
    # Filter for where T2 was actually invoked
    t2_invoked = df[df['t2_invoked'] == True].copy()
    
    # Add label for clarity
    t2_invoked['label'] = t2_invoked['sample_id'].map(id_to_label)
    
    # Cross-tab
    ct = pd.crosstab([t2_invoked['label'], t2_invoked['t2_parsed_verdict']], 
                     [t2_invoked['terminal_route'], t2_invoked['final_action']])
    return ct

print("--- LightweightDeep Routing ---")
print(audit_strat("LightweightDeep"))
print("\n--- FullCascade Routing ---")
print(audit_strat("FullCascade"))

# Also check total counts for terminal routes
for strat in ["LightweightDeep", "FullCascade"]:
    df = pd.read_csv(f"{RESULTS_DIR}/logs_{strat}.csv")
    print(f"\n{strat} Terminal Routes:\n{df['terminal_route'].value_counts()}")

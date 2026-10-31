import pandas as pd
import json

RESULTS_DIR = "revision/results"
DATASET_PATH = "revision/data/expanded_dataset.json"

with open(DATASET_PATH, 'r') as f:
    dataset = json.load(f)

id_to_cat = {s['sample_id']: s.get('attack_category', 'none') for s in dataset}
id_to_label = {s['sample_id']: s.get('label', 'benign') for s in dataset}

def analyze_strat(strat):
    df = pd.read_csv(f"{RESULTS_DIR}/logs_{strat}.csv")
    attacks = df[df['ground_truth'] == 'prohibited']
    
    res = {}
    for cat in ['direct', 'indirect_prompt_injection']:
        cat_df = attacks[attacks['attack_category'] == cat]
        tp = cat_df[cat_df['final_action'] == 'BLOCK'].shape[0]
        fn = cat_df[cat_df['final_action'] == 'ALLOW'].shape[0]
        asr = (fn / (tp + fn)) * 100 if (tp + fn) > 0 else 0
        deep_calls = cat_df['t3_invoked'].sum()
        res[cat] = {"TP": tp, "FN": fn, "ASR": asr, "DeepCalls": deep_calls}
    return res

do_res = analyze_strat("DeepOnly")
fc_res = analyze_strat("FullCascade")

print("--- DeepOnly ---")
for cat, v in do_res.items():
    print(f"{cat}: {v}")

print("\n--- FullCascade ---")
for cat, v in fc_res.items():
    print(f"{cat}: {v}")

# Verify totals
print(f"\nDeepOnly Total Attacks: {do_res['direct']['TP']+do_res['direct']['FN'] + do_res['indirect_prompt_injection']['TP']+do_res['indirect_prompt_injection']['FN']}")
print(f"FullCascade Total Attacks: {fc_res['direct']['TP']+fc_res['direct']['FN'] + fc_res['indirect_prompt_injection']['TP']+fc_res['indirect_prompt_injection']['FN']}")

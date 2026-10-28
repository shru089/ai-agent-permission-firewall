import pandas as pd
import json

RESULTS_DIR = "revision/results"
DATASET_PATH = "revision/data/expanded_dataset.json"

with open(DATASET_PATH, 'r') as f:
    dataset = json.load(f)

id_to_cat = {s['sample_id']: s.get('attack_category', 'none') for s in dataset}

def get_stats(strat):
    df = pd.read_csv(f"{RESULTS_DIR}/logs_{strat}.csv")
    attacks = df[df['ground_truth'] == 'prohibited']
    
    results = {}
    for cat in ['direct', 'indirect_prompt_injection']:
        cat_df = attacks[attacks['attack_category'] == cat]
        tp = cat_df[cat_df['final_action'] == 'BLOCK'].shape[0]
        fn = cat_df[cat_df['final_action'] == 'ALLOW'].shape[0]
        asr = (fn / (tp + fn)) * 100 if (tp + fn) > 0 else 0
        deep_calls = cat_df['t3_invoked'].sum()
        results[cat] = (tp, fn, asr, deep_calls)
    return results

do_stats = get_stats("DeepOnly")
fc_stats = get_stats("FullCascade")

print("Strategy,Category,TP,FN,ASR,DeepCalls")
for cat in ['direct', 'indirect_prompt_injection']:
    s = do_stats[cat]
    print(f"DeepOnly,{cat},{s[0]},{s[1]},{s[2]:.2f},{s[3]}")
    s = fc_stats[cat]
    print(f"FullCascade,{cat},{s[0]},{s[1]},{s[2]:.2f},{s[3]}")

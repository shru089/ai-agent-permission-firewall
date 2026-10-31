import pandas as pd
import numpy as np
import math

RESULTS_DIR = "revision/results"
STRATEGIES = ["LightweightOnly", "DeepOnly", "DeterministicDeep", "LightweightDeep", "FullCascade"]

def wilson_score_interval(count, n, confidence=0.95):
    if n == 0: return (0, 0)
    z = 1.96 # for 95%
    p = count / n
    denominator = 1 + z**2/n
    centre_adjusted_p = p + z**2/(2*n)
    adjusted_std = math.sqrt((p*(1-p)/n) + (z**2/(4*n**2)))
    lower = (centre_adjusted_p - z * adjusted_std) / denominator
    upper = (centre_adjusted_p + z * adjusted_std) / denominator
    return max(0, lower), min(1, upper)

print("--- 1. Latency Verification ---")
for strat in STRATEGIES:
    df = pd.read_csv(f"{RESULTS_DIR}/logs_{strat}.csv")
    print(f"{strat}: Count={len(df)}, Median={np.median(df['total_latency_ms'])}")

print("\n--- 3. ASR Wilson CIs ---")
print("Strategy,TP,FN,ASR,CI_Lower,CI_Upper")
for strat in STRATEGIES:
    df = pd.read_csv(f"{RESULTS_DIR}/logs_{strat}.csv")
    attacks = df[df['ground_truth'] == 'prohibited']
    tp = attacks[attacks['final_action'] == 'BLOCK'].shape[0]
    fn = attacks[attacks['final_action'] == 'ALLOW'].shape[0]
    asr = (fn / (tp + fn)) * 100 if (tp + fn) > 0 else 0
    lower, upper = wilson_score_interval(fn, tp + fn)
    print(f"{strat},{tp},{fn},{asr:.2f},{lower*100:.2f},{upper*100:.2f}")

print("\n--- 4. Category Breakdown ---")
for strat in ["DeepOnly", "FullCascade"]:
    df = pd.read_csv(f"{RESULTS_DIR}/logs_{strat}.csv")
    attacks = df[df['ground_truth'] == 'prohibited']
    if 'attack_category' not in attacks.columns:
        print(f"{strat}: No attack_category column")
        continue
        
    cats = attacks['attack_category'].unique()
    print(f"Strategy: {strat}")
    print("Category,TP,FN,ASR,DeepCalls")
    for cat in cats:
        cat_df = attacks[attacks['attack_category'] == cat]
        tp = cat_df[cat_df['final_action'] == 'BLOCK'].shape[0]
        fn = cat_df[cat_df['final_action'] == 'ALLOW'].shape[0]
        asr = (fn / (tp + fn)) * 100 if (tp + fn) > 0 else 0
        # To get deep calls for this category, we need to see where t3 was invoked
        deep_calls = cat_df['t3_invoked'].sum()
        print(f"{cat},{tp},{fn},{asr:.2f},{deep_calls}")


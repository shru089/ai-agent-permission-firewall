import pandas as pd
import os

RESULTS_DIR = "revision/results"
STRATEGIES = ["LightweightOnly", "DeepOnly", "DeterministicDeep", "LightweightDeep", "FullCascade"]

def load_df(strat):
    return pd.read_csv(f"{RESULTS_DIR}/logs_{strat}.csv")

dfs = {strat: load_df(strat) for strat in STRATEGIES}

# 1. Reconcile Deep Invocations
ld_deep = set(dfs['LightweightDeep'][dfs['LightweightDeep']['t3_invoked'] == True]['sample_id'])
fc_deep = set(dfs['FullCascade'][dfs['FullCascade']['t3_invoked'] == True]['sample_id'])
diff_ld_fc = ld_deep - fc_deep
fc_t1_blocked = set(dfs['FullCascade'][dfs['FullCascade']['t1_verdict'] == 'FAIL']['sample_id'])
diff_fc_ld = fc_deep - ld_deep

print(f"--- Requirement 1 ---")
print(f"LightweightDeep Deep IDs: {len(ld_deep)}")
print(f"FullCascade Deep IDs: {len(fc_deep)}")
print(f"Diff (LD - FC): {len(diff_ld_fc)}")
print(f"FullCascade T1 Blocked: {len(fc_t1_blocked)}")
print(f"Diff == T1 Blocked: {diff_ld_fc == fc_t1_blocked}")
print(f"Reverse Diff (FC - LD): {len(diff_fc_ld)}")

# 2. Compare Attack Allowances
do_attacks = dfs['DeepOnly'][dfs['DeepOnly']['ground_truth'] == 'prohibited']
do_allowed = set(do_attacks[do_attacks['final_action'] == 'ALLOW']['sample_id'])

fc_attacks = dfs['FullCascade'][dfs['FullCascade']['ground_truth'] == 'prohibited']
fc_allowed = set(fc_attacks[fc_attacks['final_action'] == 'ALLOW']['sample_id'])

print(f"\n--- Requirement 2 ---")
print(f"DeepOnly Allowed Attacks: {len(do_allowed)}")
print(f"FullCascade Allowed Attacks: {len(fc_allowed)}")
print(f"Intersection: {len(do_allowed & fc_allowed)}")
print(f"Sets Equal: {do_allowed == fc_allowed}")

# 3. Exact Counts & Metrics
print(f"\n--- Requirement 3 ---")
for strat in STRATEGIES:
    df = dfs[strat]
    attacks = df[df['ground_truth'] == 'prohibited']
    benign = df[df['ground_truth'] == 'benign']
    
    tp = attacks[attacks['final_action'] == 'BLOCK'].shape[0]
    fn = attacks[attacks['final_action'] == 'ALLOW'].shape[0]
    tn = benign[benign['final_action'] == 'ALLOW'].shape[0]
    fp = benign[benign['final_action'] == 'BLOCK'].shape[0]
    errors = df[df['final_action'] == 'ERROR'].shape[0]
    
    print(f"Strategy: {strat}")
    print(f"  Attacks: {len(attacks)} (TP: {tp}, FN: {fn})")
    print(f"  Benign: {len(benign)} (TN: {tn}, FP: {fp})")
    print(f"  Errors: {errors}")
    print(f"  ASR Denominator: {len(attacks)}")
    print(f"  FPR Denominator: {len(benign)}")

# 4. Paired Attack Outcome Table
print(f"\n--- Requirement 4 ---")
do_outcomes = dfs['DeepOnly'].set_index('sample_id')['final_action']
fc_outcomes = dfs['FullCascade'].set_index('sample_id')['final_action']
attacks_ids = dfs['DeepOnly'][dfs['DeepOnly']['ground_truth'] == 'prohibited']['sample_id'].tolist()

print("sample_id,ground_truth,DeepOnly,FullCascade")
for aid in attacks_ids:
    print(f"{aid},prohibited,{do_outcomes.get(aid)},{fc_outcomes.get(aid)}")


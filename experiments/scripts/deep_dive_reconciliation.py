import pandas as pd
import os

RESULTS_DIR = "revision/results"
STRATEGIES = ["LightweightOnly", "DeepOnly", "DeterministicDeep", "LightweightDeep", "FullCascade"]

def load_df(strat):
    return pd.read_csv(f"{RESULTS_DIR}/logs_{strat}.csv")

dfs = {strat: load_df(strat) for strat in STRATEGIES}

# 1. Correct Route Distribution (Mutually Exclusive)
print("--- 1. Correct Route Distribution ---")
for strat in STRATEGIES:
    df = dfs[strat]
    # We only count terminal routes
    dist = df['terminal_route'].value_counts()
    total = len(df)
    print(f"{strat}: Total={total}, Dist={dist.to_dict()}")

# 2 & 3. Analyze the 16 Disputed IDs (T1=FAIL)
print("\n--- 2 & 3. Trace for T1-Blocked IDs ---")
fc_df = dfs['FullCascade']
ld_df = dfs['LightweightDeep']
t1_fail_ids = fc_df[fc_df['t1_verdict'] == 'FAIL']['sample_id'].tolist()

print(f"Disputed IDs: {t1_fail_ids}")
print(f"{'ID':<10} | {'Strat':<16} | {'T1':<6} | {'T1Term?':<8} | {'T2Inv':<6} | {'T2Res':<6} | {'T3Inv':<6} | {'T3Res':<6} | {'Final':<6} | {'Route':<10}")
print("-" * 90)

for aid in t1_fail_ids:
    for strat, df in [("LightweightDeep", ld_df), ("FullCascade", fc_df)]:
        row = df[df['sample_id'] == aid].iloc[0]
        # T1 termination logic from run_benchmark_stable.py
        t1_term = "YES" if (strat == "FullCascade" or strat == "DeterministicDeep") and row['t1_verdict'] == 'FAIL' else "NO"
        
        print(f"{aid:<10} | {strat:<16} | {row['t1_verdict']:<6} | {t1_term:<8} | {str(row['t2_invoked']):<6} | {str(row['t2_parsed_verdict']):<6} | {str(row['t3_invoked']):<6} | {str(row['t3_parsed_verdict']):<6} | {row['final_action']:<6} | {row['terminal_route']:<10}")

# 4. ID-Set Equality for Deep Invocations
print("\n--- 4. Deep Invocation ID Set Equality ---")
ld_deep_ids = set(ld_df[ld_df['t3_invoked'] == True]['sample_id'])
fc_deep_ids = set(fc_df[fc_df['t3_invoked'] == True]['sample_id'])
fc_t1_term_ids = set(fc_df[(fc_df['t1_verdict'] == 'FAIL')]['sample_id'])

diff_ld_fc = ld_deep_ids - fc_deep_ids
diff_fc_ld = fc_deep_ids - ld_deep_ids

print(f"LD Deep IDs: {len(ld_deep_ids)}")
print(f"FC Deep IDs: {len(fc_deep_ids)}")
print(f"LD - FC: {len(diff_ld_fc)}")
print(f"FC T1 Terminal IDs: {len(fc_t1_term_ids)}")
print(f"Equality (LD-FC == FC_T1_Term): {diff_ld_fc == fc_t1_term_ids}")
print(f"Reverse Diff (FC - LD): {len(diff_fc_ld)}")

# 5. Attack ID Allow Equality
print("\n--- 5. Allowed Attack ID Equality ---")
ld_attacks = ld_df[ld_df['ground_truth'] == 'prohibited']
fc_attacks = fc_df[fc_df['ground_truth'] == 'prohibited']

ld_allowed = set(ld_attacks[ld_attacks['final_action'] == 'ALLOW']['sample_id'])
fc_allowed = set(fc_attacks[fc_attacks['final_action'] == 'ALLOW']['sample_id'])

print(f"LD Allowed Attacks: {len(ld_allowed)}")
print(f"FC Allowed Attacks: {len(fc_allowed)}")
print(f"Exact Same IDs: {ld_allowed == fc_allowed}")
if ld_allowed != fc_allowed:
    print(f"Diff (LD - FC): {len(ld_allowed - fc_allowed)}")
    print(f"Diff (FC - LD): {len(fc_allowed - ld_allowed)}")


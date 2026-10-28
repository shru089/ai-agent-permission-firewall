import pandas as pd

RESULTS_DIR = "revision/results"

def load_df(strat):
    return pd.read_csv(f"{RESULTS_DIR}/logs_{strat}.csv").set_index('sample_id')

df_do = load_df("DeepOnly")
df_fc = load_df("FullCascade")
df_ld = load_df("LightweightDeep")

# 1. DeepOnly vs FullCascade
attacks = df_do[df_do['ground_truth'] == 'prohibited'].index
do_res = df_do.loc[attacks, 'final_action']
fc_res = df_fc.loc[attacks, 'final_action']

both_block = ((do_res == 'BLOCK') & (fc_res == 'BLOCK')).sum()
do_allow_fc_block = ((do_res == 'ALLOW') & (fc_res == 'BLOCK')).sum()
do_block_fc_allow = ((do_res == 'BLOCK') & (fc_res == 'ALLOW')).sum()
both_allow = ((do_res == 'ALLOW') & (fc_res == 'ALLOW')).sum()

print(f"DeepOnly vs FullCascade: both_block={both_block}, do_allow_fc_block={do_allow_fc_block}, do_block_fc_allow={do_block_fc_allow}, both_allow={both_allow}")

# 2. LightweightDeep vs FullCascade identical decisions
all_samples = df_ld.index
ld_res = df_ld.loc[all_samples, 'final_action']
fc_res = df_fc.loc[all_samples, 'final_action']
identical = (ld_res == fc_res).all()
diff_count = (ld_res != fc_res).sum()
print(f"LD vs FC identical decisions: {identical} (diff={diff_count})")

# 3. T1 Blocked in FC reached T3 in LD
fc_t1_blocked = df_fc[df_fc['t1_verdict'] == 'FAIL'].index
ld_t3_invoked = df_ld[df_ld['t3_invoked'] == True].index
ld_t3_blocked = df_ld[(df_ld['t3_invoked'] == True) & (df_ld['final_action'] == 'BLOCK')].index

all_t1_reached_t3_ld = all(aid in ld_t3_invoked for aid in fc_t1_blocked)
all_t1_blocked_t3_ld = all(aid in ld_t3_blocked for aid in fc_t1_blocked)

print(f"FC T1 blocked ({len(fc_t1_blocked)}) reached T3 in LD: {all_t1_reached_t3_ld}")
print(f"FC T1 blocked ({len(fc_t1_blocked)}) blocked at T3 in LD: {all_t1_blocked_t3_ld}")

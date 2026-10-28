import pandas as pd
import numpy as np
import os

RESULTS_DIR = "revision/results"
STRATEGIES = ["LightweightOnly", "DeepOnly", "DeterministicDeep", "LightweightDeep", "FullCascade"]

print("Strategy,Mean,Median,p95,DeepCalls,Timeouts,Errors")
for strat in STRATEGIES:
    df = pd.read_csv(f"{RESULTS_DIR}/logs_{strat}.csv")
    lats = df['total_latency_ms'].dropna()
    deep_calls = df['t3_invoked'].sum()
    timeouts = df[df['t3_execution_status'] == 'timeout'].shape[0]
    errors = df[df['final_action'] == 'ERROR'].shape[0]
    
    print(f"{strat},{lats.mean():.2f},{np.median(lats):.2f},{np.percentile(lats, 95):.2f},{deep_calls},{timeouts},{errors}")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import os

OUT = "charts"
os.makedirs(OUT, exist_ok=True)

plt.rcParams.update({
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 9,
    "legend.fontsize": 8,
    "figure.dpi": 150,
})

# ---------------- TEST-IN data (Table 1) ----------------
arms = ["B0\nAlwaysAllow", "B1\nAlwaysDeny", "B2\nAlwaysReview", "B3\nStateless", "B4\nActionOnly", "B5\nTranscript", "B6\nStateful", "P1\nHybrid"]
apr_testin = [0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]
lts0_testin = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 0.5]
revr_testin = [0.0, 0.0, 1.0, 0.3333, 0.3333, 0.3333, 0.0833, 0.0833]
latency_testin = [0.006, 0.008, 0.008, 0.851, 1.017, 1.401, 1.337, 1.023]
j_testin = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 0.5]

# ---------------- TEST-NOVEL data (Table 2) ----------------
apr_testnovel = [0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]
lts0_testnovel = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0]
revr_testnovel = [0.0, 0.0, 1.0, 0.25, 0.25, 0.25, 0.0, 0.0]
latency_testnovel = [0.018, 0.015, 0.026, 1.341, 1.462, 1.293, 1.709, 0.936]
j_testnovel = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0]

# ---------------- Chart 1: TEST-IN grouped bar (APR, LTS-0, Review Rate) ----------------
x = np.arange(len(arms))
w = 0.26
fig, ax = plt.subplots(figsize=(10, 5))
ax.bar(x - w, apr_testin, w, label="M-APR", color="#2c7fb8")
ax.bar(x, lts0_testin, w, label="M-LTS-0", color="#7fcdbb")
ax.bar(x + w, revr_testin, w, label="M-REVR", color="#fd8d3c")
ax.set_xticks(x)
ax.set_xticklabels(arms, rotation=35, ha="right")
ax.set_ylabel("Rate (0–1)")
ax.set_title("TEST-IN Split: Attack Prevention, Uninterrupted Utility & Review Rate")
ax.legend(loc="upper right", frameon=False, ncols=3)
ax.set_ylim(0, 1.05)
ax.grid(axis="y", alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/testin_grouped.png", bbox_inches="tight")
plt.close(fig)

# ---------------- Chart 2: TEST-NOVEL grouped bar ----------------
fig, ax = plt.subplots(figsize=(10, 5))
ax.bar(x - w, apr_testnovel, w, label="M-APR", color="#2c7fb8")
ax.bar(x, lts0_testnovel, w, label="M-LTS-0", color="#7fcdbb")
ax.bar(x + w, revr_testnovel, w, label="M-REVR", color="#fd8d3c")
ax.set_xticks(x)
ax.set_xticklabels(arms, rotation=35, ha="right")
ax.set_ylabel("Rate (0–1)")
ax.set_title("TEST-NOVEL Split: Generalization Against Reserved Attack Templates")
ax.legend(loc="upper right", frameon=False, ncols=3)
ax.set_ylim(0, 1.05)
ax.grid(axis="y", alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/testnovel_grouped.png", bbox_inches="tight")
plt.close(fig)

# ---------------- Chart 3: Youden's J comparison ----------------
fig, ax = plt.subplots(figsize=(10, 5))
ax.bar(x - w/2, j_testin, w/2, label="TEST-IN", color="#f1e7d4")
ax.bar(x + w/2, j_testnovel, w/2, label="TEST-NOVEL", color="#d4e6f1")
ax.set_xticks(x)
ax.set_xticklabels(arms, rotation=35, ha="right")
ax.set_ylabel("Youden's J (0–1)")
ax.set_title("History-Dependence Detection: Youden's J on Matched Critical Pairs")
ax.legend(frameon=False)
ax.set_ylim(0, 1.1)
ax.grid(axis="y", alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/youdens_j.png", bbox_inches="tight")
plt.close(fig)

# ---------------- Chart 4: Latency comparison ----------------
fig, ax = plt.subplots(figsize=(10, 4.5))
ax.bar(x - w/2, latency_testin, w/2, label="TEST-IN", color="#6a51a3")
ax.bar(x + w/2, latency_testnovel, w/2, label="TEST-NOVEL", color="#bcbddc")
ax.set_xticks(x)
ax.set_xticklabels(arms, rotation=35, ha="right")
ax.set_ylabel("p95 Latency (ms)")
ax.set_title("Decision Latency p95 by Arm and Split (budget ceiling: 600 ms)")
ax.legend(frameon=False)
ax.axhline(600, color="red", linestyle="--", linewidth=1, label="600 ms ceiling")
ax.legend(frameon=False)
ax.grid(axis="y", alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/latency.png", bbox_inches="tight")
plt.close(fig)

# ---------------- Chart 5: Hypothesis outcomes ----------------
hyps = ["H1\nInvariance", "H2\nStateful vs Transcript", "H3\nReview Burden", "H4\nZero Violations", "H5\nLatency"]
outcomes = [1, 1, 1, 1, 1]
colors = ["#2ca02c"] * 5
fig, ax = plt.subplots(figsize=(8, 3))
bars = ax.bar(hyps, outcomes, color=colors, width=0.5)
for b in bars:
    ax.text(b.get_x() + b.get_width()/2, b.get_height() - 0.05, "CONFIRMED", ha="center", va="bottom", color="white", fontweight="bold", fontsize=9)
ax.set_ylim(0, 1.25)
ax.set_ylabel("Outcome (1=Confirmed)")
ax.set_title("Pre-Registered Hypotheses H1–H5: All Confirmed")
ax.set_yticks([])
ax.grid(axis="y", alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/hypotheses.png", bbox_inches="tight")
plt.close(fig)

# ---------------- Chart 6: APR vs LTS-0 scatter (security vs utility tradeoff) ----------------
fig, ax = plt.subplots(figsize=(7, 5))
for i, arm in enumerate(arms):
    ax.scatter(lts0_testin[i], apr_testin[i], s=120, label=arm.split("\n")[0])
ax.plot([0, 1], [0, 1], "k--", alpha=0.3)
ax.set_xlabel("M-LTS-0 (Uninterrupted Utility)")
ax.set_ylabel("M-APR (Attack Prevention)")
ax.set_title("Security vs Utility Tradeoff — TEST-IN Split")
ax.set_xlim(-0.05, 1.05)
ax.set_ylim(-0.05, 1.05)
ax.legend(frameon=False, fontsize=7, loc="lower right")
ax.grid(alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/tradeoff.png", bbox_inches="tight")
plt.close(fig)

print("Charts generated:")
for f in sorted(os.listdir(OUT)):
    print(" -", f)

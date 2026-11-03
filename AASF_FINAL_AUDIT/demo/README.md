# AASF Demonstration Suite (Demos A–F)

This directory contains standalone, reproducible demonstration artifacts for the **Adaptive Agentic Security Firewall (AASF)**.

## Files in this Directory
- `runnable_demo.py`: Main executable script executing Demos A through F.
- `sample_inputs/`: Input payloads in canonical `ActionRequest` JSON format.
- `actual_outputs/`: Output responses in canonical `FirewallResponse` JSON format.
- `execution_traces/`: Plain text step-by-step terminal execution traces.

## How to Run
To run all demonstrations:
```bash
python runnable_demo.py
```

To run a specific demonstration:
```bash
python runnable_demo.py --demo F
```


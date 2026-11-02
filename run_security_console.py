"""
Adaptive Agentic Security Firewall (AASF) - Interactive Security Console Launcher.
Starts the local runtime console web server connecting directly to FirewallCore.
Usage:
    python run_security_console.py [--port 8000] [--host 127.0.0.1]
"""

import argparse
import sys
import uvicorn


def print_startup_banner(host: str, port: int) -> None:
    line = "=" * 80
    print(line)
    print("      ADAPTIVE AGENTIC SECURITY FIREWALL (AASF) - RUNTIME SECURITY CONSOLE")
    print(line)
    print(" * Architecture: In-Process Controlled Interception (FirewallCore)")
    print(" * Enforced Security Invariants: INV-01 through INV-12")
    print(" * Real Components: PolicyEngine, Decision Combinator, State Fold Phi,")
    print("                    ControlledExecutor, TokenStore, AuditStore, ReviewService")
    print(" * Cryptographic Engine: SHA-256 State Hashing | HMAC-SHA256 Single-Use Tokens")
    print("-" * 80)
    print(f" -> Access Interactive Console at: http://{host}:{port}")
    print(" -> Four Live Consoles Available:")
    print("    [A] Agent Simulator       - Custom action request generation & dispatch")
    print("    [B] Firewall Inspector    - 9-Stage execution trace & sub-ms latency")
    print("    [C] Human Review Console  - Real-time review queue, approvals & TOCTOU defense")
    print("    [D] Audit Explorer        - Cryptographic hash-chain & tamper simulation")
    print(" -> 10 Preset Scenarios (SCEN-01 to SCEN-10) selectable via top ribbon")
    print(line)
    print(" Press Ctrl+C to terminate the console server.\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="AASF Interactive Security Console")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port number (default: 8000)")
    args = parser.parse_args()

    print_startup_banner(args.host, args.port)

    # Start Uvicorn ASGI server
    uvicorn.run(
        "console.server:app",
        host=args.host,
        port=args.port,
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()


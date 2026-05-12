# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Tonkl Protocol, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@tonkl.com**

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Scope

This policy covers:
- `tonkl-node` — the Rust node (RPC, P2P, consensus, state)
- `tonkl-prover` — the ZK witness solver
- `tonkl-website` — the Next.js web wallet and API routes
- ZK circuits (`tonkl-transfer`, `tonkl-merge`, `tonkl-split`, `tonkl-mint`)

## Known Limitations (Alpha)

This is alpha software. Known limitations include:
- Proof verification can be disabled only with the explicit `--allow-unverified-local` loopback development override
- RPC write authentication can be disabled only with the explicit `--allow-unauthenticated-rpc-local` loopback development override
- Metadata-heavy RPC reads require `TONKL_RPC_SECRET` unless `--allow-public-rpc-metadata` is deliberately enabled
- P2P mDNS discovery is disabled by default and can be enabled only with `--allow-mdns-local` on loopback outside beta/production
- The default faucet key (`0xface70`) is public and for testnet use only
- P2P gossip does not yet validate block signatures (round-robin trust model)
- No slashing or stake-based consensus

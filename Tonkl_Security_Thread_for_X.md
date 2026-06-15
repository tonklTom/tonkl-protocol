# Tonkl Security Pass — X Thread (copy/paste)

Each block below is one tweet. Trim to taste.

---

**1/**
We ran a full security pass on Tonkl before testnet — a privacy blockchain where every transaction is shielded with zero-knowledge proofs.

Found and fixed a critical counterfeiting bug (the Zcash class), then hardened the rest.

Here's what we found 🧵

---

**2/**
Context: Tonkl is a UTXO privacy chain. Balances, amounts, and sender/receiver are hidden on-chain — only ZK proofs are visible.

Noir circuits → UltraHonk proofs, Poseidon2 hashing, a Merkle tree of note commitments + a nullifier set to stop double-spends.

---

**3/** 🔴 The critical one
To spend, you prove your notes exist in the chain's Merkle tree, anchored to a "root." The node verified the proof… but never checked that the root was a *real* committed chain root.

A valid proof against a tree you invented = money from nothing.

---

**4/**
Same class as the classic Zcash counterfeiting flaw: the proof verifies perfectly, but a missing check lets you spend notes that never existed — for any asset, bypassing the mint authority entirely.

The tell: the rejection error existed in the code, wired to nothing.

---

**5/** The fix
The node now persists every committed Merkle root and rejects any spend not anchored to one. Enforced at mempool admission AND block application, on every code path.

Verified live on a testnet: real transfers pass, forged-anchor ones get rejected.

---

**6/** Also caught + fixed
• Proof verification could "fail open" if keys weren't loaded → now fail-closed
• A block producer that skipped supply-cap checks
• Consolidated every consensus check into one gate so a future code path can't silently skip it

---

**7/** On the crypto side
The Poseidon2 hash had no input-length separation, so hash(a,b) == hash(a,b,0). Not exploitable today, but fragile.

Added per-arity domain tags, recompiled all circuits, regenerated the verification keys, and proved Noir↔Rust hashing parity.

---

**8/** The honest part
This is alpha, testnet-only, no real value. And a manual review is NOT a formal audit.

For a shielded pool the dangerous bugs are silent — you don't get a crash, you get quiet loss. An independent circuit audit is still a hard requirement before launch.

---

**9/**
Net: a strong cryptographic core, one serious node-side hole (now closed + verified), and a clear list of what's left before a public testnet.

Privacy tech is unforgiving. The boring checks are the ones that matter.

---

## Optional: single-post version

We ran a pre-testnet security pass on Tonkl (a ZK privacy blockchain) and found a critical counterfeiting bug — the node verified spend proofs but never checked they were anchored to a *real* chain root, so a valid proof against a made-up tree could mint money from nothing (the Zcash class of bug).

Now fixed: every committed root is persisted, and any spend not anchored to one is rejected on every path — verified live. Also hardened proof verification (fail-closed), supply-cap enforcement, and the Poseidon2 hash.

Still alpha, testnet-only, and a manual review isn't a formal audit — an external circuit audit is a hard requirement before launch.

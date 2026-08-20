# data/

Runtime state. **Nothing in this directory is committed** (see `.gitignore`).

| path | contents |
|---|---|
| `pool/anu-NNNNNN.bin` | harvested ANU blocks, packed at 6 bits per character |
| `pool/index.db` | block hashes for deduplication, plus consume-once bookkeeping |
| `beamline.db` | API key hashes, usage counters, and the beacon pulse chain |

Two reasons this stays out of version control. The archive is the raw entropy that
seeded beacon pulses which have already been published and signed, so releasing it
would expose the material behind them. And `beamline.db` holds key hashes and usage
history.

Populate the archive with:

    python scripts/harvest_anu.py --duration 600

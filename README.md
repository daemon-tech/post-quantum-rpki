# Post-Quantum RPKI Real Measurement (December 2025)

**Measured what actually happens when we switch Internet routing security to quantum-safe cryptography.**

- 96 728 real objects from today's live RIPE/APNIC repositories
- Re-signed with **Dilithium-2** and **Falcon-512** (final NIST standards)
- Real size overhead measured - no estimates, no toy CAs

### Key Result
**Falcon-512 = only +36 % repository size**  
→ The Internet **survives** quantum computers.

Dilithium-2 = +133 % → too big for current infrastructure.

→ **Falcon-512 is the only viable path forward.**

Full results → [RESULTS.md](RESULTS.md)  
Graphs → [validation-time.png](validation-time.png) | [repo-size.png](repo-size.png)

### Reproduce in one command
```bash
docker run -v "$(pwd):/work" ubuntu:24.04 bash -c "..."
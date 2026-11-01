# Tamarin model of FogRoam

Formal model and proofs, in the [Tamarin prover](https://tamarin-prover.com), of FogRoam,
the two-phase authentication protocol proposed in
*"FogRoam: Secure Authentication with Cloud-Free Handover for 6G Vehicular Networks"*.

* **Phase A** (cloud-assisted): vehicle `V_i` → fog node `F_j` → cloud server `CS`
  → `F_j` → `V_i` (messages M1–M4, session key `SK` shared by the three parties).
* **Phase B** (cloud-free handover): `V_i` ↔ new fog node `F_k`
  (messages M5–M6, session key `SK'`), authenticated with the pairwise key
  `k_ik = f(VID_i, FID_k)` of the bivariate polynomial `f`.

## Files

| File | Content |
|------|---------|
| `IoV_AKA.spthy` | complete model (both phases, all lemmas) |
| `IoV_AKA_phaseA.spthy` | shared setup, registration, and adversary rules with phase A |
| `IoV_AKA_phaseB.spthy` | shared setup, registration, and adversary rules with phase B |
| `oracle.py` | goal-ranking oracle used for all proofs (one ranking per group of lemmas, selected by lemma name) |
| `run_all.sh` | proves every lemma and writes `results/summary.txt` |
| `results/` | summary and Tamarin output of every lemma |

The phase files contain exactly the rules of `IoV_AKA.spthy` that belong to the
respective phase together with the shared rules. All hashes carry phase-specific
tags, so that no message of one phase can be used in the other; proving the lemmas
of each phase on its own file keeps the proof search tractable.

## Threat model

Dolev–Yao network adversary extended with the Canetti–Krawczyk queries:

* `Corrupt_V`, `Corrupt_F`, `Corrupt_CS` (with `*_share` and `Corrupt_CS_db`): reveal
  the long-term state of a vehicle (private key, static key `k_ic`, row share of `f`),
  of a fog node (private key, static key `k_jc`, column share of `f`), or of the cloud
  server (private key, registry, polynomial `f`);
* `ESReveal_V`, `ESReveal_F`, `ESReveal_CS`: reveal the ephemeral randomness `r` of any
  session.

## Modelling choices

* Scalar multiplication `x·P` is Tamarin's Diffie–Hellman exponentiation `P^x`.
* Ephemeral scalars follow NAXOS: `x = h(r || sk)`.
* The static keys `k_ic = h(sk_i·pk_c)` and `k_jc = h(sk_j·pk_c)` are fresh values shared
  at registration and revealed by corrupting either endpoint.
* The pairwise key `k_ij = f(VID_i, FID_j)` is the private function `poly/2`; it is
  revealed by corrupting `V_i`, `F_j`, or `CS` (coalitions larger than the degrees of
  `f` are outside the model).
* The one-time pad `N_c = h(.) XOR SK` is modelled as symmetric encryption.
* Timestamp checks are modelled by replay caches (uniqueness restrictions).

## Lemmas

| Lemma | Property |
|-------|----------|
| `ltk_V`, `ltk_F`, `key_ic`, `key_jc`, `key_ij` | helper: long-term secrets are only learnt through corruption |
| `eph_V`, `eph_F`, `eph_C` | helper: a NAXOS scalar `h(r‖sk)` is only learnt if both `r` and `sk` are revealed |
| `exec_phaseA`, `exec_phaseB` | executability (honest runs exist) |
| `authA_V_F`, `authA_V_CS` | `V_i` authenticates `F_j` and `CS` (agreement on all session values, KCI-resilient) |
| `authA_F_V`, `authA_F_CS` | `F_j` authenticates `V_i` and `CS` |
| `authA_CS_V`, `authA_CS_F` | `CS` authenticates `V_i` and `F_j` (a compromised fog node cannot impersonate a vehicle to `CS`) |
| `authB_V_F`, `authB_F_V` | mutual authentication of `V_i` and `F_k` in phase B |
| `secA_vehicle`, `secA_fog`, `secA_cloud` | secrecy of `SK`, including perfect forward secrecy and ephemeral-secret leakage |
| `secB_vehicle`, `secB_fog` | secrecy of `SK'`, including perfect forward secrecy and ephemeral-secret leakage |
| `anonymity` | the identity `VID_i` is never learnt by an outsider |
| `no_escrow_V`, `no_escrow_F` | a corrupted `CS` never learns `sk_i` or `sk_j` |

The secrecy lemmas allow the adversary to corrupt every entity after the session and
to reveal every ephemeral secret, and exclude only the full exposure (long-term key
and ephemeral secret) of one entity of the session and the corruption of a partner
before the session. Since `CS` shares `k_ic` and `k_jc` with all entities, `secA_cloud`
also excludes the corruption of `CS` itself before its instance accepts; likewise,
since a fog node authenticates vehicles with the symmetric key `k_ik`, which it can
compute itself, `secB_fog` excludes the corruption of `F_k` or `CS` before `F_k`
accepts.

## Running

Tested with Tamarin 1.10.0 and Maude 3.5.

```bash
JOBS=2 ./run_all.sh     # proves all lemmas, two Tamarin processes in parallel
# a single lemma:
tamarin-prover --prove=secA_vehicle --heuristic=O --oraclename=oracle.py IoV_AKA_phaseA.spthy
```

`tamarin-prover interactive .` can be used to inspect the proofs (select the
oracle heuristic `O` with `--heuristic=O --oraclename=oracle.py`).

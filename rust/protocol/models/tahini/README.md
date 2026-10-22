<!--
Copyright 2026 Aurora Naska and Cas Cremers.
SPDX-License-Identifier: CC-BY-4.0
-->

# Formal Security Analysis of Tahini Session Management

May 2025, [Aurora Naska](https://auroranaska.github.io/), [Cas Cremers](https://people.cispa.io/cas.cremers/index.html).

This folder contains the formal security analysis of Tahini Session Management using the [Tamarin Prover](https://tamarin-prover.com/). <br/> 
Tahini refines the proposal from the following works: <br/>  
- "Impossibility Results for Post-Compromise Security in Real-World Communication Systems" [2] and  
- "Formal Analysis of Session-Handling in Secure Messaging: Lifting Security from Sessions to Conversations" [3]. 

### Formal Security Analysis Artifact

The folder contains three files defining protocol models and their security properties:
- [Sesame.spthy](Sesame.spthy) - The abstracted model of Sesame's session management [1] with an unbounded number of sessions, instead of N=40 sessions.
- [Proposal.spthy](Proposal.spthy) -  The model proposed in [2], defining a policy of sequential sessions and N=2 number of sessions (active and inactive).
- [Tahini.spthy](Tahini.spthy) - Signal's new session management: the model refines the Proposal.spthy model by adding a restriction to archive an active session after a threshold of 5 missed chances to perform the DH ratchet.

These models are based on the work in [2] and [3], and refined during the development of Tahini.

Additionally we provide:
- [Analysis_scope.md](Analysis_scope.md) - Notes on the scope of our analysis.

#### Reproducing Results
We provide commands to reproduce our proofs of Post-Compromise Security(PCS) against a session compromise.
We first provide the command-lines for sanity checking the models, and then for the main theorem and respective helper lemmas.

To prove the sanity traces execute from the main directory:

```
tamarin-prover --prove=SANITY\* Sesame.spthy
tamarin-prover --prove=SANITY\* Proposal.spthy
tamarin-prover --prove=SANITY\* Tahini.spthy
```

To prove the main theorems execute:

```
tamarin-prover --prove=PROVE\* Sesame.spthy
tamarin-prover --prove=PROVE\* Proposal.spthy
tamarin-prover --prove=PROVE\* Tahini.spthy
```
#### Expected Output
Tamarin will verify all sanity checks in the three models.
Tamarin will verify the main theorem of PCS in Tahini.spthy and Proposal.spthy, and falsify it in Sesame.spthy.

The main theorem for PCS against a dynamic state compromise is defined in `lemma PROVE_ConversationPCS_SessionCompromise`. <br/> 

A detailed copy of the expected outputs from Tamarin is prepended at the beginning of each file.

> [!NOTE]
> The property in the `Sesame.spthy` model falsifies because older sessions can be used by an attacker to encrypt and decrypt new messages [3].

#### Tamarin Prover version
All models are verified on Tamarin version:
```
Generated from:
Tamarin version 1.11.0
Maude version 3.2
Git revision: 32705dd3717361574fc8dada786d4930a3b7ad29, branch: develop
Compiled at: 2025-10-31 15:29:59.721353832 UTC
```

### References
--------
 - [1] Moxie Marlinspike, Trevor Perrin. [The Sesame Algorithm: Session Management for Asynchronous Message Encryption](https://signal.org/docs/specifications/sesame/) 
 - [2] Cas Cremers, Niklas Medinger, Aurora Naska. [Impossibility Results for Post-Compromise Security
in Real-World Communication Systems](https://eprint.iacr.org/2024/1886), IEEE S&P 2025
 - [3] Cas Cremers, Charlie Jacomme, Aurora Naska. [Formal Analysis of Session-Handling in Secure Messaging: Lifting Security from Sessions to Conversations](https://eprint.iacr.org/2022/1710), USENIX 2023

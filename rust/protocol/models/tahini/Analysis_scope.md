<!--
Copyright 2026 Aurora Naska and Cas Cremers.
SPDX-License-Identifier: CC-BY-4.0
-->

# Analysis Scope 

This formal security analysis shows that the new Tahini session management policies preserve the Post-Compromise Security (PCS) guarantee against a session compromise. The analysis is performed on manually crafted abstract formal models and property specifications, which are then formally analyzed using the Tamarin prover.

#### Models and Analysis

We manually crafted abstract models of the session management and the underlying ratcheting protocol, and their intended security properties.

The base model [Sesame.spthy](Sesame.spthy) abstracts the Sesame session management protocol, in which the underlying Signal protocol component is modeled as a state-loss-resilient protocol as defined in [1,2]. 
We prove that Post-Compromise Security (PCS) does not hold at the conversation level under dynamic state compromise. 
We do not consider long-term identity compromise, as PCS is unachievable in state-loss-resilient systems, as shown in [1]. 

In [Proposal.spthy](Proposal.spthy), we introduce session policies and prove that PCS holds under dynamic state compromise [1]. 

Finally, [Tahini.spthy](Tahini.spthy) restricts the Proposal model to discard the current active session in desynchronized cases, 
 and we show that PCS is still preserved.

#### Limitations

To make the formal proofs feasible, we had to make trade-offs with the level of detail captured in these models. 

For example, our models capture simultaneously initialized sessions, and not the full details of the asynchronicity of the key exchange. As a result, the analysis has a limited view of the desynchronization reasons and their effects. However, if parties do end up desynchronized, they are restricted to discard the older session upon detecting this desynchronization, i.e., start a new session on defined threshold.

Moreover, our models strongly abstract the protocols that determine the details of individual ratcheting chains, i.e., the key exchange and the ratcheting protocol, which we consider in a black-box fashion similar to [1]. In future extensions one could consider modeling these in more detail to formally prove that they do not have undesired interference effects.

### References
--------
 - [1] Cas Cremers, Niklas Medinger, Aurora Naska. [Impossibility Results for Post-Compromise Security
in Real-World Communication Systems](https://eprint.iacr.org/2024/1886), IEEE S&P 2025
 - [2] Cas Cremers, Charlie Jacomme, Aurora Naska. [Formal Analysis of Session-Handling in Secure Messaging: Lifting Security from Sessions to Conversations](https://eprint.iacr.org/2022/1710), USENIX 2023


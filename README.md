# Inductive Compliance: Lightweight & Noninvasive Transition-Gated Security for Declarative Infrastructure

Inductive Compliance is a noninvasive model for transition-centric policy gating that revolves around authorizing state transitions `T` from abstract projected states `A` to `B` over defined context predicates.

## The Process

Here is the basic step-by-step process of how Inductive Compliance works.

Assume a policy-compliant device in configuration state `A` wants to transition to configuration state `B`
1. Attestation server tracks abstract state `A`
2. Device sends a request to the Attestation Server with guarded atomic transition `T`
3. After validating T, the attestation server signs and sends a token `V` authorizing transition from state `A` to state `B`
4. Device begins build transition with token `V`. The authorized builder verifies the signed token `V`, checking that the predecessor state matches `A` and the successor state matches `B`
5. If checks pass, the build is successful and the device transitions from `A` to `B`

## Explanation of the Proof of Concept

The Proof of Concept available here is a basic NixOS configuration that models the inductive compliance process across a small base of 6 configuration fields, those being:

```
attestation
services.openssh.enable
services.openssh.passwordAuthentication
services.openssh.permitRootLogin
networking.firewall.enable
networking.firewall.allowedTCPPorts
```

On a high level, the builder verification is implemented as a python script during NixOS' build phase. It takes the projected NixOS config (the 6 options above) as a JSON file input, and verifies it to the token JSON by comparing the hashes of each field. If the python script fails to verify the token or the config, it will cause the builder to fail. It achieves this by registering itself as a dependency for the NixOS configuration: `system.extraDependencies = [ verifyDrv ]`;.

That's about it! The verification just checks if the hash of `A` and the hash of `B` match the hashes in the token, and verifies the signature from the server from the public key field in `attestation`. If so, it returns successfully.

### Why NixOS?

The use of NixOS for this PoC was an intentional choice. NixOS conveniently exposes system and service options like openssh and firewall settings in its declarative config, greatly simplifying implementation. Additionally, Nix/NixOS' focus on reproducible builds fits naturally with the requirements of policy compliance. We aim to minimize state, and declarative configs are perfect for controlling system state. Additionally, the aforementioned `system.extraDependencies` option also conveniently allows us to implement a local build/activation gate. Overall, NixOS presented itself as a really convenient medium to implement a functional, practical prototype of Inductive Compliance.

## The Caveats

To reap the full benefits of inductive compliance, it is absolutely crucial that the underlying policy is well-defined. The strength of this system is that it separates security configuration from state. Therefore, how secure you system is depends on how well you can maintain that separation.

Inductive compliance works best if you can successfully separate and define your configuration such that any local changes applied to `A'` that do not affect its projected state `A` compromise its security within your defined policy. Naturally, this implies that a sufficiently rigid security policy is best practice.

Inductive trust works on the principle of induction. If a base state is compliant with a policy, and a transition maintains compliance, the following states are also compliant by induction. We do currently have to rely on more traditional methods to ensure that the base starting state is compliant. To take fleet systems as an example, the first deploy can be enforced compliant and signed by the distributor. The various fleet systems can then diverge in exact configuration and still maintain compliance.

## Future Work

In this example, the server tracks the exact contents of `A` after every update. This is simply done for ease of implementation. In a realistic example, `A` can be tracked, verified and updated using merkle trees and other forms of Zero Knowledge Proofs. The client, during step \[1], can attest via its merkle root to confirm that it is in configuration state `A`. The server, can also sign and calculate the new merkle root after applying transition T, signing state `B` without tracking the exact contents of `A`.

Additionally, the Proof of Concept defines 'atomic' as a policy relevant field transition that varies by exactly 1 field value. However, this is not necessarily the only definition that 'atomic' can take. 'Atomic' transitions are enforced in order to minimize insecure intermediate states when transitioning multiple security fields at once. 'Atomic' transitions mitigate this risk by removing these intermediate states. In reality, the nix builder is sandboxed and these transitions might not even yield such insecure states. Nonetheless, it may be useful to define what 'atomic' means for transitions in your secure system.

## Citation

If you build on this work (either this proof-of-concept or Inductive Compliance) in research, talks, or derivative implementations, refer to the `CITATION.cff` file in this repository.

## Closest Adjacent Literature

While this particular implementation of inductive compliance is novel to the best of my knowledge, I do recognize surrounding work like 'NixFleet Compliance' aim to solve similar problems with fundamentally different strategies. While NixFleet Compliance aims to provide declarative compliance controls throughout the medium of NixOS, similar to this proposal, NixFleet only measures final state compliance. NixFleet, to the best of my knowledge:
- Does not model predecessor-aware state transitions.
- Does not model 'temporary compliance' or ideologies surrounding it.
- Is a more fixed-state compliance gate for fleet systems.


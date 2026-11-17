# Out-of-Band SPDM Hardware Attestation

## Overview

Enterprise AI platforms attach accelerators, DPUs and fabric switches which host
their own firmware and microcontrollers. Host-bound TPM 2.0 measurements cannot
see these peripherals: they live behind PCIe config space or independent SoCs.
In zero-trust bare-metal deployments, tenants additionally prohibit in-band
agents, so the node's OS cannot be relied upon to collect evidence at all.

Keylime therefore supports **out-of-band (OOB) attestation** based on DMTF SPDM
(DSP0274) collected over Redfish (DSP0268 `ComponentIntegrity`). The BMC acts as
the SPDM requester; each peripheral's hardware root of trust signs its
measurement hashes. Keylime appraises the signed measurements out-of-band,
without any software in the tenant OS.

## Architecture

```
 Management plane                  BMC network                    PCIe / MCTP
 ---------------                  ------------                    -----------
 Verifier <--v3 REST--> OOB collector <--Redfish--> BMC (SPDM requester) <---> peripheral RoTs (responders)
     |
 Registrar <-- device cert chains (X.509/DICE)
```

The **OOB collector** (`keylime_oob_attest`, `keylime/oob/`) is a standalone
loop, deployable as a container in the management plane. Each cycle it:

1. negotiates `spdm_measurements` evidence with the verifier using the v3
   push-mode attestation protocol;
2. translates the verifier's freshness challenge (nonce) into a Redfish
   `SPDMGetSignedMeasurements` action on the BMC;
3. submits the signed DSP0274 MEASUREMENTS responses as evidence.

The **registrar** accepts SPDM device certificate chains in addition to TPM
EK/IAK/IDevID identities. Chains are validated against a configurable trust
store (`registrar/spdm_cert_store`). Agents registered this way have no AK and
are activated directly; the chain is treated as immutable identity on
re-registration.

The **SPDM engine** (`keylime/verification/spdm_engine.py`) is registered for
the `spdm_measurements` evidence type (evidence class `certification`) and
verifies:

1. the device certificate chain against the trust store;
2. the device's signature over the measurements message;
3. the nonce embedded in the message against the verifier-issued challenge
   (freshness); and
4. the measurement blocks against an optional JSON reference policy
   (`verifier/spdm_measurement_policy`, mapping block indexes to expected hex
   values). Without a policy, signature/freshness/trust checks apply only.

## Dual-factor attestation (2FA)

An agent may provide both `tpm_quote` and `spdm_measurements` evidence in the
same attestation. Both engines must pass: neither the TPM engine nor the SPDM
engine downgrades a `fail` evaluation recorded by the other, so host state
(kernel/IMA) and peripheral integrity are enforced together before secrets are
released.

## Revocation

Verification failures are tagged with the `spdm_attestation` component and flow
into the existing ZeroMQ/webhook revocation framework, which downstream
consumers (e.g., OpenShift node controllers) can use to cordon, drain or
quarantine nodes.

## Limitations / future work

- The collector's Redfish client covers `ComponentIntegrity` discovery and the
  `SPDMGetSignedMeasurements` action only; additional BMC implementations may
  require minor adaptation.
- CoRIM/CoMID appraisal (RFC 9334 reference manifests) is future work; today a
  simple JSON reference policy is used.
- Enrollment of fully TPM-less agents with the verifier (currently TPM-centric)
  is not yet streamlined; the SPDM evidence flow itself is agent-agnostic.

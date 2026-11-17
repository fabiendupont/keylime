"""Out-of-band (OOB) SPDM attestation support for Keylime.

This package implements the OOB collector, a standalone component which polls
a BMC's Redfish ComponentIntegrity endpoints (DMTF DSP0268), translates the
Keylime verifier's freshness challenges into Redfish SPDMGetSignedMeasurements
actions, and submits the resulting signed SPDM measurements (DMTF DSP0274) to
the verifier as `spdm_measurements` evidence.

The collector runs outside the tenant OS (e.g., as a container in the
management plane), which is what makes the attestation "agentless" from the
tenant node's perspective.
"""

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **FIDO2 / CTAP2.1 authenticator applet for JavaCard**, running on the Secure Element (SE) of a BMC board. It is a fork of the open-source [BryanJacobs/FIDO2Applet](https://github.com/BryanJacobs/FIDO2Applet), extended by BMC with **fingerprint (biometric UV)** support.

The applet does **not** talk to the fingerprint sensor directly. It runs on the SE, while the fingerprint sensor is wired to a separate MCU. The MCU firmware (companion project `bmc_msc_ccid_hid_uac_bm`, mounted as the second folder in `bfidoapplet.code-workspace`) exposes the authenticator to the host as a USB **CTAPHID** device and bridges sensor operations. Understanding almost any biometric behavior requires reading both sides — see "The SE ↔ MCU sensor bridge" below.

- Package AID `A000000647`, applet AID `A0000006472F0001`, `FIRMWARE_VERSION = 0x05` (see [.jcop](.jcop) and [FIDO2Applet.java](src/com/bmc/fido2/FIDO2Applet.java)).

## Build

This is an **Eclipse + NXP JCOP** project — there is no Maven/Gradle/Ant/CLI build. Building the CAP requires the NXP JCOP Eclipse plugin toolchain:

- Target: **JavaCard 3.0.4 API + GlobalPlatform 2.2.1**, Oracle Cap Converter (see [.classpath](.classpath) and [.jcop](.jcop)).
- The Eclipse builders `com.nxp.id.jcop.eclipse.jcopbuilder` / `jcopbuildverifier` ([.project](.project)) compile `src/` → `bin/` and convert to a CAP.
- There is no test suite in this repo. Functional testing is done against real/emulated hardware over CTAPHID (e.g. the Python `fido2` / `python-fido2` client libraries), not via in-repo unit tests.

When editing, respect JavaCard constraints: no `int`/`long`/`String`/generics/garbage collection assumptions; only `short`/`byte`, fixed-size arrays, and `javacard.*` / `javacardx.*` APIs. Instance fields are **persistent (EEPROM)** unless explicitly backed by `JCSystem.makeTransientByteArray(...)`.

## Architecture

### Command dispatch
Everything enters through [`FIDO2Applet.process()`](src/com/bmc/fido2/FIDO2Applet.java) (~line 3470). It:
1. Handles applet SELECT, U2F (`CLA/INS` `0x0001/0x0002/0x0003`), APDU command chaining, and outgoing-response continuation (`GET RESPONSE`, `0x00C0`).
2. Detects the **sensor-result APDU** `CLA=0x80 INS=0xF1` from the MCU and routes it to `handleBioSensorResult()`.
3. Otherwise requires `CLA=0x80 INS=0x10` (CTAP2 `NFCCTAP_MSG`), reads the request via `fullyReadReq(...)`, and switches on the first CTAP command byte (`CMD_*` in [FIDOConstants.java](src/com/bmc/fido2/FIDOConstants.java)): makeCredential, getAssertion, getInfo, clientPIN, reset, credentialManagement, largeBlobs, config, **bioEnrollment (0x09)**, etc.

CBOR is parsed and emitted **by hand** with a running `readIdx`/`writeIdx` cursor — there is no CBOR library. Errors are returned by `sendErrorByte(apdu, CTAP2_ERR_*)` / `ISOException.throwIt(...)`.

### Memory model
Set up in `initTransientStorage()` and the constructor (config lives at the bottom of the file, ~line 7620+):
- `bufferMem` — the main request/response buffer (`BUFFER_MEM_SIZE`, default 1024). Placed in **RAM if it fits**, otherwise flash (`getTempOrFlashByteBuffer`). `makeCredential`/`getAssertion` always buffer the full request into `bufferMem` (`forceBuffering=true`), which is why the request survives the multi-round-trip bio flow.
- `BufferManager` — scratch allocator handing out slices of transient RAM / flash scratch (`MAX_RAM_SCRATCH_SIZE`, `FLASH_SCRATCH_SIZE`).
- `TransientStorage` — per-session/per-request transient flags (chaining offsets, iteration pointers, permissions in use, authenticator enable/disable).
- Resident keys are persistent, allocated in batches (`ResidentKeyData`, `NUM_RESIDENT_KEY_SLOTS_PER_BATCH`).

### Install-time configuration
`install()` parses a **CBOR map of overrides** from the install parameters (keys `0x00`+). Defaults are set first in the constructor (`LOW_SECURITY_MAXIMUM_COMPLIANCE`, `FORCE_ALWAYS_UV`, `USE_LOW_SECURITY_FOR_SOME_RKS`, `PIN_KDF_ITERATIONS`, `BUFFER_MEM_SIZE`, etc.), then overridden. Changing security/compliance behavior usually means changing a default here or passing an install override, not hardcoding logic.

### The SE ↔ MCU sensor bridge (most important cross-cutting design)
The SE cannot reach the fingerprint sensor, so the applet drives it through the MCU using a **multi-round-trip proprietary protocol**:

1. When the applet needs a sensor operation it puts a `SC_BIO_*` command in the response body and **throws `ISOException 0x91F0`** (`SW_BIO_SENSOR_CONTROL`).
2. The MCU firmware ([source/smartcard_bio_bridge.c](../../../../Projects/USB2025/USB-Audio/SC/bmc/bmc_msc_ccid_hid_uac_bm/source/smartcard_bio_bridge.c)) sees `0x91F0`, performs the sensor operation, and sends the result back as a fresh APDU **`CLA=0x80 INS=0xF1 P1=<sensor status word> P2=0x00 [Lc data]`**.
3. `process()` routes `INS=0xF1` to `handleBioSensorResult()`, which advances a **state machine** keyed by `bioEnrollPhase` (`CAPTURE → GENCHAR → SEARCH_DUP → REGMODEL → STORE` for enrollment; `UV_CAPTURE → UV_GENCHAR → UV_SEARCH` for verification; plus `DELETE`). Each phase either throws `0x91F0` again (next sensor op) or produces a final CTAP response.
4. During the long biometric wait the MCU ([source/hid/hid_fido2_bridge.c](../../../../Projects/USB2025/USB-Audio/SC/bmc/bmc_msc_ccid_hid_uac_bm/source/hid/hid_fido2_bridge.c)) emits **CTAPHID_KEEPALIVE (0xBB)** reports (`PROCESSING` / `USER_NEEDED`) so the host client does not time out — this is the "CTAP alive" behavior.

Biometric UV re-dispatch: when a `makeCredential`/`getAssertion` needs UV and `bioEnrolled` is true, the applet saves the pending command (`bioUvPendingCmd`/`bioUvPendingLc`) and starts UV verification. On a fingerprint match, `handleBioSensorResult` sets `bioUvVerified=true` and **re-invokes the original command from `bufferMem`**, which then treats UV as satisfied. The `SC_BIO_*` sensor opcodes, `BIO_*` CTAP2 bioEnrollment constants, and status codes are all defined in [FIDOConstants.java](src/com/bmc/fido2/FIDOConstants.java).

## Key files

| File | Role |
|------|------|
| `FIDO2Applet.java` (~8k lines) | Everything: dispatch, CTAP2 commands, CBOR, crypto, and the bio bridge/state machine |
| `FIDOConstants.java` | CTAP `CMD_*`/error codes, and the BMC bio additions (`SC_BIO_*`, `BIO_*`, `SW_BIO_SENSOR_CONTROL`, `INS_BIO_SENSOR_RESULT`) |
| `CannedCBOR.java` | Pre-serialized CBOR fragments (getInfo response, extension IDs, AAGUID, etc.) |
| `BufferManager.java` / `TransientStorage.java` | Scratch memory allocation and per-session transient state |
| `ResidentKeyData.java` | Persistent discoverable-credential storage |
| `P256Constants.java` / `SigOpCounter.java` / `PinRetryCounter.java` | secp256r1 params, signature counter, PIN retry counter |

## Working with the companion firmware

The MCU firmware project is a separate NXP MCUXpresso codebase in the workspace. FIDO-relevant sources: `source/hid/hid_fido2_bridge.c` (CTAPHID transport, INIT/CBOR/keepalive), `source/hid/apdu_translator.c` (CTAPHID payload ↔ APDU), `source/smartcard_bio_bridge.c` (the `0x91F0`/`0xF1` sensor loop), `source/biometric_uv.c`, and `source/fingerprint/` (sensor command layer). Any change to the `SC_BIO_*` opcodes, the `0x91F0`/`0xF1` framing, or the sensor status-word encoding must be kept in sync on **both** sides.

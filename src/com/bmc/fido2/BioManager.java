package com.bmc.fido2;

import javacard.framework.*;

/**
 * Added by MP: biometric (fingerprint) subsystem, extracted from FIDO2Applet.
 *
 * Owns all fingerprint state and the multi-round-trip sensor protocol with the MCU:
 * the applet emits an SC_BIO_* command and throws SW=0x91F0 (SW_BIO_SENSOR_CONTROL); the MCU performs
 * the sensor operation and replies with a fresh APDU CLA=0x80 INS=0xF1, which lands in
 * {@link #handleSensorResult(APDU)} and advances the state machine keyed by bioEnrollPhase.
 *
 * This class is deliberately kept in the same package as {@link FIDO2Applet}: it reaches back into the
 * applet (package-private members) for shared buffers, CBOR/APDU helpers and for re-dispatching the
 * command that was paused while the fingerprint was being read.
 */
final class BioManager {

    /** The owning applet - used for shared buffers, helpers and command re-dispatch. */
    private final FIDO2Applet applet;

    /** True if biometric (fingerprint) templates are enrolled on the device */
    private boolean bioEnrolled;

    BioManager(FIDO2Applet applet) {
        this.applet = applet;
        initBioEnrollment();
    }

    // ─────────────────────────────────────────────────────────────
    //  Bio Enrollment – Sensor control helper
    // ─────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────
    //  Bio Enrollment – Main command handler
    // ─────────────────────────────────────────────────────────────

    // Enrollment session state
    private boolean bioEnrollActive;
    private byte bioEnrollSamplesRemaining;
    private byte bioEnrollSampleIndex;
    private short bioEnrollPageId;
    private byte[] bioEnrollTemplateId;

    // Bio template persistent storage (mirrors bio_template_name_t in firmware ctap_bio_enrollment.c)
    private byte[] bioTemplateFriendlyName;
    private short bioTemplateFriendlyNameLen;
    /**
     * Enrollment phase tracking for multi-round-trip sensor control.
     * 0 = idle
     * 1 = waiting for GetEnrollImage result (capture)
     * 2 = waiting for GenChar result (template generation)
     * 3 = waiting for Search result (duplicate check)
     * 4 = waiting for RegModel result (merge templates)
     * 5 = waiting for StoreChar result (save to sensor flash)
     * 6 = waiting for DeleteChar result (remove enrollment)
     */
    private byte bioEnrollPhase;
    private static final byte BIO_PHASE_IDLE           = 0;
    private static final byte BIO_PHASE_CAPTURE        = 1;
    private static final byte BIO_PHASE_GENCHAR        = 2;
    private static final byte BIO_PHASE_SEARCH_DUP     = 3;
    private static final byte BIO_PHASE_REGMODEL       = 4;
    private static final byte BIO_PHASE_STORE          = 5;
    private static final byte BIO_PHASE_DELETE         = 6;

    // UV verification phases (biometric user verification for makeCredential/getAssertion)
    private static final byte BIO_PHASE_UV_CAPTURE     = 7;
    private static final byte BIO_PHASE_UV_GENCHAR     = 8;
    private static final byte BIO_PHASE_UV_SEARCH      = 9;

    // Sensor validation phase (verify templates exist in sensor on getInfo)
    private static final byte BIO_PHASE_CHECK_ENROLLED = 10;

    // Added by MP: clear any stale sensor template (page 10) at the start of a fresh enrollment,
    // so re-installing the applet (which wipes bioEnrolled) doesn't collide with a template still
    // physically stored in the sensor's own flash. Result advances to BIO_PHASE_CAPTURE.
    private static final byte BIO_PHASE_ENROLL_PREDELETE = 11;

    /**
     * Biometric UV verification state.
     * When makeCredential/getAssertion needs UV and bioEnrolled is true,
     * the applet drives a fingerprint verification flow via sensor control.
     * After successful verification, the pending command is re-executed.
     */
    private boolean bioUvVerified;
    private byte bioUvPendingCmd;
    private short bioUvPendingLc;

    // Added by MP: built-in UV (fingerprint) retry tracking for the standards-compliant
    // getPinUvAuthTokenUsingUvWithPermissions / getUVRetries flow. Transient (CLEAR_ON_RESET):
    // failures reset to zero on power cycle, matching CTAP2.1 uvRetries semantics.
    private static final byte BIO_UV_MAX_RETRIES = 5;
    private byte[] bioUvFailCount;

    /**
     * Flag indicating that a reset command is pending after bio sensor
     * deletion completes. When applet.authenticatorReset() finds bioEnrolled==true,
     * it sends a sensor delete command and sets this flag. After the sensor
     * responds, handleBioSensorResult() re-dispatches the reset.
     */
    private boolean resetPendingAfterBioDelete;

    /**
     * Initialize bio enrollment resources (call from install)
     */
    private void initBioEnrollment() {
        bioEnrollTemplateId = new byte[2];
        bioEnrollActive = false;
        bioEnrollSamplesRemaining = 0;
        bioEnrollSampleIndex = 0;
        bioEnrollPageId = 10; // Fixed page ID for single-slot enrollment
        bioEnrollPhase = BIO_PHASE_IDLE;
        bioUvVerified = false;
        bioUvPendingCmd = 0;
        bioUvPendingLc = 0;
        bioEnrolled = false;
        bioTemplateFriendlyName = new byte[FIDOConstants.BIO_MAX_FRIENDLY_NAME_LEN];
        bioTemplateFriendlyNameLen = 0;
        // Added by MP: transient UV failure counter (resets on power cycle)
        bioUvFailCount = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
    }

    /**
     * Start biometric UV verification via sensor control protocol.
     * Saves the pending command state and requests a fingerprint capture
     * from the MCU sensor. The multi-round-trip flow continues in
     * handleBioSensorResult() through phases UV_CAPTURE → UV_GENCHAR → UV_SEARCH.
     *
     * On success, handleBioSensorResult re-dispatches the pending command
     * with bioUvVerified=true, so makeCredential/getAssertion proceeds with UV flag set.
     *
     * @param apdu Request/response object
     */
    private void startBioUvVerification(APDU apdu) {
        bioEnrollPhase = BIO_PHASE_UV_CAPTURE;
        byte[] apduBuf = apdu.getBuffer();
        apduBuf[0] = FIDOConstants.SC_BIO_CAPTURE_IMAGE;
        apduBuf[1] = 0x00;
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 2);
        apdu.sendBytes((short) 0, (short) 2);
        ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
    }

    /**
     * Handles authenticatorBioEnrollment (0x09) CTAP2.1 command.
     *
     * The applet maintains CTAP2 protocol state (PIN token verification,
     * enrollment session) while delegating physical fingerprint sensor
     * operations to the MCU via proprietary APDUs.
     *
     * @param apdu      Request/response object
     * @param reqBuffer Buffer containing incoming request
     * @param lc        Length of incoming request
     */
    private void bioEnrollmentSubcommand(APDU apdu, byte[] reqBuffer, short lc) {
        short readIdx = (short) 1; // Skip cmd byte

        if (lc < 2) {
            applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            return;
        }

        byte mapEntryCount = (byte)applet.getMapEntryCount(apdu, reqBuffer[readIdx]);
        readIdx++;

        // Parse request parameters
        byte subCommand = 0;
        boolean hasSubCommand = false;
        boolean hasModality = false;
        byte modality = 0;
        boolean getModality = false;
        byte pinProtocol = 0;
        boolean hasPinProtocol = false;
        short pinAuthIdx = -1;
        short pinAuthLen = 0;
        short subCmdParamsIdx = -1;
        short subCmdParamsLen = 0;

        for (short i = 0; i < mapEntryCount; i++) {
            if (readIdx >= lc) {
                applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                return;
            }

            byte key = reqBuffer[readIdx++];

            switch (key) {
                case FIDOConstants.BIO_REQ_MODALITY: // 0x01 modality
                    modality = reqBuffer[readIdx++];
                    hasModality = true;
                    break;
                case FIDOConstants.BIO_REQ_SUBCOMMAND: // 0x02 subCommand
                    subCommand = reqBuffer[readIdx++];
                    hasSubCommand = true;
                    break;
                case FIDOConstants.BIO_REQ_SUB_COMMAND_PARAMS: // 0x03 subCommandParams
                    // Store offset and skip CBOR data
                    subCmdParamsIdx = readIdx;
                    readIdx = applet.consumeAnyEntity(apdu, reqBuffer, readIdx, lc);
                    subCmdParamsLen = (short)(readIdx - subCmdParamsIdx);
                    break;
                case FIDOConstants.BIO_REQ_PIN_UV_AUTH_PROTOCOL: // 0x04 pinUvAuthProtocol
                    pinProtocol = reqBuffer[readIdx++];
                    hasPinProtocol = true;
                    break;
                case FIDOConstants.BIO_REQ_PIN_UV_AUTH_PARAM: // 0x05 pinUvAuthParam
                    if ((reqBuffer[readIdx] & 0xE0) == 0x40 || (reqBuffer[readIdx] & 0xE0) == 0x50) {
                        // Byte string
                        pinAuthIdx = readIdx;
                        readIdx = applet.consumeAnyEntity(apdu, reqBuffer, readIdx, lc);
                        pinAuthLen = (short)(readIdx - pinAuthIdx);
                    } else {
                        readIdx = applet.consumeAnyEntity(apdu, reqBuffer, readIdx, lc);
                    }
                    break;
                case FIDOConstants.BIO_REQ_GET_MODALITY: // 0x06 getModality
                    if (reqBuffer[readIdx] == (byte) 0xF5) { // CBOR true
                        getModality = true;
                    }
                    readIdx++;
                    break;
                default:
                    // Skip unknown keys
                    readIdx = applet.consumeAnyEntity(apdu, reqBuffer, readIdx, lc);
                    break;
            }
        }

        // Handle getModality (no PIN auth required)
        if (getModality) {
            bioSendModalityResponse(apdu);
            return;
        }

        if (!hasSubCommand) {
            applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            return;
        }

        // getFingerprintSensorInfo: no PIN auth required
        if (subCommand == FIDOConstants.BIO_ENROLL_GET_SENSOR_INFO) {
            bioSendSensorInfoResponse(apdu);
            return;
        }

        // All other subcommands require pinUvAuth with be permission
        if (!hasPinProtocol || pinAuthIdx < 0) {
            applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
            return;
        }

        applet.checkPinProtocolSupported(apdu, pinProtocol);

        // Added by MP: actually verify pinUvAuthParam (previously only its presence was required).
        // Per CTAP2.1, the token must carry the "be" (bioEnrollment) permission, and pinUvAuthParam
        // must authenticate the message: modality || subCommand || subCommandParams.
        if ((applet.transientStorage.getPinPermissions() & FIDOConstants.PERM_BIO_ENROLLMENT) == 0x00) {
            // Token lacks the bioEnrollment permission
            applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
        }

        // Locate the raw pinUvAuthParam bytes, skipping the CBOR byte-string header
        short pinAuthDataIdx;
        if (reqBuffer[pinAuthIdx] == 0x58) { // one-byte length form (e.g. protocol 2: 0x58 0x20 ..)
            pinAuthDataIdx = (short)(pinAuthIdx + 2);
        } else { // in-place length form 0x4X (e.g. protocol 1: 0x50 ..)
            pinAuthDataIdx = (short)(pinAuthIdx + 1);
        }

        // Assemble the verification message into scratch: modality || subCommand || subCommandParams
        final short bioMsgLen = (short)(2 + (subCmdParamsIdx == -1 ? 0 : subCmdParamsLen));
        final short bioMsgHandle = applet.bufferManager.allocate(apdu, bioMsgLen, BufferManager.ANYWHERE);
        final short bioMsgOff = applet.bufferManager.getOffsetForHandle(bioMsgHandle);
        final byte[] bioMsgBuf = applet.bufferManager.getBufferForHandle(apdu, bioMsgHandle);
        bioMsgBuf[bioMsgOff] = modality;
        bioMsgBuf[(short)(bioMsgOff + 1)] = subCommand;
        if (subCmdParamsIdx != -1 && subCmdParamsLen > 0) {
            Util.arrayCopyNonAtomic(reqBuffer, subCmdParamsIdx,
                    bioMsgBuf, (short)(bioMsgOff + 2), subCmdParamsLen);
        }

        // Verify. Do NOT invalidate the token: a single enrollment spans enrollBegin + repeated
        // enrollCaptureNext commands, all sharing the same token.
        applet.checkPinToken(apdu, bioMsgBuf, bioMsgOff, bioMsgLen,
                reqBuffer, pinAuthDataIdx, pinProtocol, false);
        applet.bufferManager.release(apdu, bioMsgHandle, bioMsgLen);

        // Dispatch sub-command
        switch (subCommand) {
            case FIDOConstants.BIO_ENROLL_BEGIN:
                bioEnrollBeginWithSensor(apdu);
                break;
            case FIDOConstants.BIO_ENROLL_CAPTURE_NEXT:
                bioEnrollCaptureNextWithSensor(apdu);
                break;
            case FIDOConstants.BIO_ENROLL_CANCEL:
                bioEnrollActive = false;
                // Empty success response
                applet.bufferMem[0] = FIDOConstants.CTAP2_OK;
                applet.doSendResponse(apdu, (short) 1);
                break;
            case FIDOConstants.BIO_ENROLL_ENUMERATE:
                bioEnumerateEnrollments(apdu);
                break;
            case FIDOConstants.BIO_ENROLL_SET_NAME:
                bioSetFriendlyName(apdu, reqBuffer, subCmdParamsIdx, subCmdParamsLen, lc);
                break;
            case FIDOConstants.BIO_ENROLL_REMOVE:
                bioRemoveEnrollment(apdu, reqBuffer, subCmdParamsIdx, subCmdParamsLen);
                break;
            default:
                applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_SUBCOMMAND);
                break;
        }
    }

    /**
     * Send getModality response
     */
    private void bioSendModalityResponse(APDU apdu) {
        byte[] buffer = applet.bufferMem;
        short offset = 0;

        buffer[offset++] = FIDOConstants.CTAP2_OK;
        buffer[offset++] = (byte) 0xA1; // map(1)
        buffer[offset++] = FIDOConstants.BIO_RESP_MODALITY;
        buffer[offset++] = FIDOConstants.BIO_MODALITY_FINGERPRINT;

        applet.doSendResponse(apdu, offset);
    }

    /**
     * Send getFingerprintSensorInfo response (via MCU sensor query)
     */
    private void bioSendSensorInfoResponse(APDU apdu) {
        byte[] buffer = applet.bufferMem;
        short offset = 0;

        buffer[offset++] = FIDOConstants.CTAP2_OK;
        buffer[offset++] = (byte) 0xA3; // map(3)

        // fingerprintKind: touch (0x01)
        buffer[offset++] = FIDOConstants.BIO_RESP_FINGERPRINT_KIND;
        buffer[offset++] = FIDOConstants.BIO_FINGERPRINT_KIND_TOUCH;

        // maxCaptureSamplesReqd
        buffer[offset++] = FIDOConstants.BIO_RESP_MAX_SAMPLES;
        buffer[offset++] = FIDOConstants.BIO_SAMPLES_REQUIRED;

        // maxTemplateFriendlyName
        buffer[offset++] = 0x08; // key for maxTemplateFriendlyName
        buffer[offset++] = (byte) 0x18; // CBOR uint (1-byte follows)
        buffer[offset++] = FIDOConstants.BIO_MAX_FRIENDLY_NAME_LEN;

        applet.doSendResponse(apdu, offset);
    }

    /**
     * enrollBegin: Start enrollment, capture first sample via MCU sensor.
     *
     * This method sends sensor control requests to the MCU by returning
     * SW=0x91F0. The MCU executes the sensor operation and sends back the
     * result as a new APDU with INS=0xF1. The process() dispatcher detects
     * INS=0xF1 and stores the result.
     *
     * Since JavaCard cannot do multi-round-trip within a single APDU exchange
     * using ISOException, the enrollment flow works differently:
     *
     * Instead of requesting sensor operations inline, the applet returns
     * SW=0x91F0 with the sensor command in the response body. The MCU intercepts
     * this, executes the command, and sends the result back as a new APDU.
     * This process repeats until the applet returns a final SW=0x9000 response.
     */
    private void bioEnrollBeginWithSensor(APDU apdu) {
        // Single-slot: if already enrolled, must remove first
        if (bioEnrolled) {
            applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_KEY_STORE_FULL);
            return;
        }
        // Start enrollment session with fixed page ID
        bioEnrollActive = true;
        bioEnrollPageId = 10;
        bioEnrollTemplateId[0] = (byte)(bioEnrollPageId >> 8);
        bioEnrollTemplateId[1] = (byte)(bioEnrollPageId & 0xFF);
        bioEnrollSamplesRemaining = FIDOConstants.BIO_SAMPLES_REQUIRED;
        bioEnrollSampleIndex = 1;

        // Added by MP: pre-delete the (single) sensor slot before capturing, so a stale template
        // left in the sensor from a previous applet installation cannot trigger a false duplicate
        // during SEARCH_DUP. Enrolling into the single slot is an overwrite by design. The delete
        // result is ignored (the slot may already be empty) — see BIO_PHASE_ENROLL_PREDELETE.
        bioEnrollPhase = BIO_PHASE_ENROLL_PREDELETE;
        byte[] apduBuf = apdu.getBuffer();
        apduBuf[0] = FIDOConstants.SC_BIO_DELETE_TEMPLATE;
        apduBuf[1] = 0x00;
        // Data: [start_page_hi] [start_page_lo] [count_hi] [count_lo]
        apduBuf[2] = (byte)(bioEnrollPageId >> 8);
        apduBuf[3] = (byte)(bioEnrollPageId & 0xFF);
        apduBuf[4] = 0x00;
        apduBuf[5] = 0x01;
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 6);
        apdu.sendBytes((short) 0, (short) 6);
        ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
    }

    /**
     * Handle sensor result APDU from MCU (INS=0xF1).
     * Dispatches to the appropriate enrollment phase handler based on bioEnrollPhase.
     *
     * State machine:
     *   CAPTURE  → (success) → send GenChar     → phase=GENCHAR
     *   GENCHAR  → (success) → send Search      → phase=SEARCH_DUP
     *   SEARCH   → (no dup)  → sample++
     *              if samples_remaining>0        → send enroll response (more samples)
     *              if samples_remaining==0       → send RegModel  → phase=REGMODEL
     *   REGMODEL → (success) → send StoreChar   → phase=STORE
     *   STORE    → (success) → enrollment done!  → send final response
     *   DELETE   → (any)     → send delete result
     */
    private void handleBioSensorResult(APDU apdu) {
        byte[] apduBytes = apdu.getBuffer();

        // P1:P2 = sensor operation status word from MCU
        short sensorSW = Util.getShort(apduBytes, ISO7816.OFFSET_P1);
        short amtRead = apdu.setIncomingAndReceive();
        short dataLen = apdu.getIncomingLength();

        switch (bioEnrollPhase) {

            case BIO_PHASE_ENROLL_PREDELETE:
                // Added by MP: result of the pre-enrollment slot clear. Ignore the status (the slot
                // may legitimately have been empty) and proceed to capture the first sample.
                bioEnrollPhase = BIO_PHASE_CAPTURE;
                apduBytes[0] = FIDOConstants.SC_BIO_GET_ENROLL_IMAGE;
                apduBytes[1] = 0x00;
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) 2);
                apdu.sendBytes((short) 0, (short) 2);
                ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
                break;

            case BIO_PHASE_CAPTURE:
                // Result of GetEnrollImage
                if (sensorSW != (short) 0x9000) {
                    byte status = mapSensorSWToSampleStatus(sensorSW);
                    bioEnrollPhase = BIO_PHASE_IDLE;
                    bioSendEnrollResponse(apdu, status);
                    return;
                }
                // Image captured → request GenChar
                bioEnrollPhase = BIO_PHASE_GENCHAR;
                apduBytes[0] = FIDOConstants.SC_BIO_GENERATE_TEMPLATE;
                apduBytes[1] = bioEnrollSampleIndex; // P2 = buffer_id
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) 2);
                apdu.sendBytes((short) 0, (short) 2);
                ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
                break;

            case BIO_PHASE_GENCHAR:
                // Result of GenChar
                if (sensorSW != (short) 0x9000) {
                    byte status = mapSensorSWToSampleStatus(sensorSW);
                    bioEnrollPhase = BIO_PHASE_IDLE;
                    bioSendEnrollResponse(apdu, status);
                    return;
                }
                // GenChar succeeded → duplicate check via Search
                bioEnrollPhase = BIO_PHASE_SEARCH_DUP;
                apduBytes[0] = FIDOConstants.SC_BIO_SEARCH_FINGER;
                apduBytes[1] = 0x00;
                // Data: [buffer_id] [start_page_hi] [start_page_lo] [page_count_hi] [page_count_lo]
                apduBytes[2] = bioEnrollSampleIndex;
                apduBytes[3] = 0x00;
                apduBytes[4] = 0x0A; // start_page = 10
                apduBytes[5] = 0x00;
                apduBytes[6] = 0x0A; // page_count = 10
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) 7);
                apdu.sendBytes((short) 0, (short) 7);
                ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
                break;

            case BIO_PHASE_SEARCH_DUP:
                // Result of Search (duplicate check)
                // If search found match (sensorSW=0x9000 and data[0]=0x01) → duplicate
                if (sensorSW == (short) 0x9000 && dataLen >= 1
                    && apduBytes[apdu.getOffsetCdata()] == 0x01) {
                    bioEnrollActive = false;
                    bioEnrollPhase = BIO_PHASE_IDLE;
                    bioSendEnrollResponse(apdu, FIDOConstants.BIO_SAMPLE_EXISTS);
                    return;
                }
                // No duplicate → sample captured successfully
                bioEnrollSampleIndex++;
                bioEnrollSamplesRemaining--;

                if (bioEnrollSamplesRemaining == 0) {
                    // All samples captured → merge templates
                    bioEnrollPhase = BIO_PHASE_REGMODEL;
                    apduBytes[0] = FIDOConstants.SC_BIO_REG_MODEL;
                    apduBytes[1] = 0x00;
                    apdu.setOutgoing();
                    apdu.setOutgoingLength((short) 2);
                    apdu.sendBytes((short) 0, (short) 2);
                    ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
                } else {
                    // More samples needed → return intermediate response
                    bioEnrollPhase = BIO_PHASE_IDLE;
                    bioSendEnrollResponse(apdu, FIDOConstants.BIO_SAMPLE_GOOD);
                }
                break;

            case BIO_PHASE_REGMODEL:
                // Result of RegModel (template merge)
                if (sensorSW != (short) 0x9000) {
                    bioEnrollActive = false;
                    bioEnrollPhase = BIO_PHASE_IDLE;
                    applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
                    return;
                }
                // Merge succeeded → store template
                bioEnrollPhase = BIO_PHASE_STORE;
                apduBytes[0] = FIDOConstants.SC_BIO_STORE_TEMPLATE;
                apduBytes[1] = 0x01; // buffer_id = 1
                apduBytes[2] = (byte)(bioEnrollPageId >> 8);
                apduBytes[3] = (byte)(bioEnrollPageId & 0xFF);
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) 4);
                apdu.sendBytes((short) 0, (short) 4);
                ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
                break;

            case BIO_PHASE_STORE:
                // Result of StoreChar (template stored to sensor flash)
                bioEnrollActive = false;
                bioEnrollPhase = BIO_PHASE_IDLE;
                if (sensorSW != (short) 0x9000) {
                    applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
                    return;
                }
                // Enrollment complete!
                bioEnrolled = true;
                bioSendEnrollResponse(apdu, FIDOConstants.BIO_SAMPLE_GOOD);
                break;

            case BIO_PHASE_DELETE:
                // Result of DeleteChar
                bioEnrollPhase = BIO_PHASE_IDLE;
                if (sensorSW == (short) 0x9000) {
                    bioEnrolled = false;
                    bioTemplateFriendlyNameLen = 0;
                }

                // If this deletion was triggered by applet.authenticatorReset(),
                // re-dispatch the reset command now that sensor cleanup is done.
                if (resetPendingAfterBioDelete) {
                    // bioEnrolled is now false (or sensor failed, proceed anyway)
                    // Re-enter authenticatorReset which will skip the sensor
                    // deletion branch and proceed with the main reset transaction.
                    applet.authenticatorReset(apdu);
                    return;
                }

                // Normal (non-reset) deletion: return success
                applet.bufferMem[0] = FIDOConstants.CTAP2_OK;
                applet.doSendResponse(apdu, (short) 1);
                break;

            // ─── UV Verification Phases (biometric user verification) ───

            case BIO_PHASE_UV_CAPTURE:
                // Result of CaptureImage for UV verification
                if (sensorSW != (short) 0x9000) {
                    bioEnrollPhase = BIO_PHASE_IDLE;
                    bioUvPendingCmd = 0;
                    applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
                    return;
                }
                // Image captured → generate template in buffer 1
                bioEnrollPhase = BIO_PHASE_UV_GENCHAR;
                apduBytes[0] = FIDOConstants.SC_BIO_GENERATE_TEMPLATE;
                apduBytes[1] = 0x01; // buffer_id = 1
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) 2);
                apdu.sendBytes((short) 0, (short) 2);
                ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
                break;

            case BIO_PHASE_UV_GENCHAR:
                // Result of GenChar for UV verification
                if (sensorSW != (short) 0x9000) {
                    bioEnrollPhase = BIO_PHASE_IDLE;
                    bioUvPendingCmd = 0;
                    applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
                    return;
                }
                // Template generated → search enrolled templates for match
                bioEnrollPhase = BIO_PHASE_UV_SEARCH;
                apduBytes[0] = FIDOConstants.SC_BIO_SEARCH_FINGER;
                apduBytes[1] = 0x00;
                // Data: [buffer_id=1] [start_page_hi=0] [start_page_lo=0] [count_hi] [count_lo]
                apduBytes[2] = 0x01; // buffer_id
                apduBytes[3] = 0x00;
                apduBytes[4] = 0x00; // start_page = 0
                apduBytes[5] = 0x00;
                apduBytes[6] = (byte) 0x64; // page_count = 100 (search all)
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) 7);
                apdu.sendBytes((short) 0, (short) 7);
                ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
                break;

            case BIO_PHASE_UV_SEARCH:
                // Result of Search for UV verification
                bioEnrollPhase = BIO_PHASE_IDLE;
                if (sensorSW == (short) 0x9000 && dataLen >= 1
                    && apduBytes[apdu.getOffsetCdata()] == 0x01) {
                    // Fingerprint matched — UV verified!
                    bioUvVerified = true;
                    bioUvFailCount[0] = 0; // Added by MP: reset UV retry counter on success
                    byte pendingCmd = bioUvPendingCmd;
                    short pendingLc = bioUvPendingLc;
                    bioUvPendingCmd = 0;
                    bioUvPendingLc = 0;

                    // Clear applet.bufferManager and re-initialize APDU buffer for clean re-entry
                    applet.bufferManager.clear();
                    applet.bufferManager.initializeAPDU(apdu);
                    applet.bufferManager.informAPDUBufferAvailability(apdu, (short) 0xFF);

                    // Re-dispatch the pending command from saved applet.bufferMem data
                    if (pendingCmd == FIDOConstants.CMD_MAKE_CREDENTIAL) {
                        applet.makeCredential(apdu, pendingLc, applet.bufferMem);
                    } else if (pendingCmd == FIDOConstants.CMD_GET_ASSERTION) {
                        applet.getAssertion(apdu, pendingLc, applet.bufferMem, (short) 0);
                    } else if (pendingCmd == FIDOConstants.CMD_CLIENT_PIN) {
                        // Added by MP: re-dispatch getPinUvAuthTokenUsingUvWithPermissions
                        applet.clientPINSubcommand(apdu, applet.bufferMem, pendingLc);
                    } else {
                        bioUvVerified = false;
                        applet.sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_OTHER);
                    }
                } else {
                    // No match — UV verification failed
                    byte failedCmd = bioUvPendingCmd; // Added by MP
                    bioUvPendingCmd = 0;
                    // Added by MP: count the failure on EVERY path (token and ad-hoc). Previously only the
                    // clientPIN token path was counted, so fingerprint matching via makeCredential/getAssertion
                    // could be retried without limit.
                    if (bioUvFailCount[0] < BIO_UV_MAX_RETRIES) {
                        bioUvFailCount[0]++;
                    }
                    if (bioUvFailCount[0] >= BIO_UV_MAX_RETRIES) {
                        // Retries exhausted for this power cycle, on either path
                        applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UV_BLOCKED);
                    } else if (failedCmd == FIDOConstants.CMD_CLIENT_PIN) {
                        // Standards token flow expects a UV-specific error
                        applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UV_INVALID);
                    } else {
                        // Ad-hoc UV path: keep the original error code so existing clients behave the same
                        applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_OPERATION_DENIED);
                    }
                }
                return;

            default:
                // Unknown phase
                bioEnrollPhase = BIO_PHASE_IDLE;
                applet.sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_OTHER);
                break;
        }
    }

    /**
     * Build and send enrollment status response
     */
    private void bioSendEnrollResponse(APDU apdu, byte sampleStatus) {
        byte[] buffer = applet.bufferMem;
        short offset = 0;

        buffer[offset++] = FIDOConstants.CTAP2_OK;

        // Determine map size: templateId + sampleStatus + remaining
        byte mapSize = (byte)(bioEnrollActive ? 3 : 2);
        buffer[offset++] = (byte)(0xA0 | mapSize); // CBOR map

        if (bioEnrollActive) {
            // templateId (byte string)
            buffer[offset++] = FIDOConstants.BIO_RESP_TEMPLATE_ID;
            buffer[offset++] = (byte)(0x40 | 2); // bstr(2)
            buffer[offset++] = bioEnrollTemplateId[0];
            buffer[offset++] = bioEnrollTemplateId[1];
        }

        // lastEnrollSampleStatus
        buffer[offset++] = FIDOConstants.BIO_RESP_LAST_SAMPLE_STATUS;
        buffer[offset++] = sampleStatus; // unsigned int

        // remainingSamples
        buffer[offset++] = FIDOConstants.BIO_RESP_REMAINING_SAMPLES;
        buffer[offset++] = bioEnrollSamplesRemaining;

        applet.doSendResponse(apdu, offset);
    }

    /**
     * captureNextSample: Capture next enrollment sample via MCU sensor.
     */
    private void bioEnrollCaptureNextWithSensor(APDU apdu) {
        if (!bioEnrollActive) {
            applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NOT_ALLOWED);
            return;
        }

        bioEnrollPhase = BIO_PHASE_CAPTURE;

        // Request GetEnrollImage from MCU
        byte[] apduBuf = apdu.getBuffer();
        apduBuf[0] = FIDOConstants.SC_BIO_GET_ENROLL_IMAGE;
        apduBuf[1] = 0x00;
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 2);
        apdu.sendBytes((short) 0, (short) 2);
        ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
    }

    /**
     * Enumerate enrolled fingerprints from persistent store.
     */
    private void bioEnumerateEnrollments(APDU apdu) {
        byte[] buffer = applet.bufferMem;
        short offset = 0;

        buffer[offset++] = FIDOConstants.CTAP2_OK;
        buffer[offset++] = (byte) 0xA1; // map(1)
        buffer[offset++] = FIDOConstants.BIO_RESP_TEMPLATE_INFOS;

        if (!bioEnrolled) {
            buffer[offset++] = (byte) 0x80; // array(0)
        } else {
            buffer[offset++] = (byte) 0x81; // array(1) — single slot

            // templateInfo map: templateId + optional friendlyName
            boolean hasName = bioTemplateFriendlyNameLen > 0;
            byte mapSize = (byte)(hasName ? 2 : 1);
            buffer[offset++] = (byte)(0xA0 | mapSize);

            // templateId (subCommandParams key 0x01 per CTAP2.1 spec §6.7)
            buffer[offset++] = FIDOConstants.BIO_SUBCMD_PARAM_TEMPLATE_ID;
            buffer[offset++] = (byte)(0x40 | 2); // bstr(2)
            buffer[offset++] = (byte)(bioEnrollPageId >> 8);
            buffer[offset++] = (byte)(bioEnrollPageId & 0xFF);

            // templateFriendlyName (subCommandParams key 0x02, optional)
            if (hasName) {
                buffer[offset++] = FIDOConstants.BIO_SUBCMD_PARAM_FRIENDLY_NAME;
                if (bioTemplateFriendlyNameLen <= 23) {
                    buffer[offset++] = (byte)(0x60 | bioTemplateFriendlyNameLen); // tstr(n)
                } else {
                    buffer[offset++] = 0x78; // tstr, 1-byte length follows
                    buffer[offset++] = (byte) bioTemplateFriendlyNameLen;
                }
                Util.arrayCopy(bioTemplateFriendlyName, (short) 0, buffer, offset, bioTemplateFriendlyNameLen);
                offset += bioTemplateFriendlyNameLen;
            }
        }

        applet.doSendResponse(apdu, offset);
    }

    /**
     * Store friendly name for an enrolled fingerprint template.
     * Parses subCommandParams CBOR map to extract templateId and templateFriendlyName,
     * then persists the name (similar to bio_set_friendly_name in firmware ctap_bio_enrollment.c).
     */
    private void bioSetFriendlyName(APDU apdu, byte[] reqBuffer, short paramsIdx, short paramsLen, short lc) {
        if (paramsIdx < 0 || paramsLen <= 0) {
            applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            return;
        }
        if (!bioEnrolled) {
            applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_FINGERPRINTS);
            return;
        }

        // Parse subCommandParams CBOR map
        short readIdx = paramsIdx;
        short endIdx = (short)(paramsIdx + paramsLen);

        byte mapCount = (byte) applet.getMapEntryCount(apdu, reqBuffer[readIdx]);
        readIdx++;

        short nameIdx = -1;
        short nameLen = 0;
        boolean hasTemplateId = false;

        for (short i = 0; i < mapCount && readIdx < endIdx; i++) {
            byte key = reqBuffer[readIdx++];

            switch (key) {
                case FIDOConstants.BIO_SUBCMD_PARAM_TEMPLATE_ID: // 0x01
                    hasTemplateId = true;
                    readIdx = applet.consumeAnyEntity(apdu, reqBuffer, readIdx, lc);
                    break;
                case FIDOConstants.BIO_SUBCMD_PARAM_FRIENDLY_NAME: { // 0x02
                    // Parse CBOR text string (major type 3)
                    short s = applet.ub(reqBuffer[readIdx]);
                    if (s >= 0x0060 && s <= 0x0077) {
                        // Short text string: length 0-23
                        nameLen = (short)(s - 0x0060);
                        readIdx++;
                        nameIdx = readIdx;
                        readIdx += nameLen;
                    } else if (s == 0x0078) {
                        // Text string with 1-byte length
                        readIdx++;
                        nameLen = applet.ub(reqBuffer[readIdx]);
                        readIdx++;
                        nameIdx = readIdx;
                        readIdx += nameLen;
                    } else {
                        // Unsupported encoding or byte string — skip
                        readIdx = applet.consumeAnyEntity(apdu, reqBuffer, readIdx, lc);
                    }
                    break;
                }
                default:
                    readIdx = applet.consumeAnyEntity(apdu, reqBuffer, readIdx, lc);
                    break;
            }
        }

        if (!hasTemplateId) {
            applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            return;
        }

        if (nameIdx >= 0 && nameLen > 0 && nameLen <= FIDOConstants.BIO_MAX_FRIENDLY_NAME_LEN) {
            Util.arrayCopy(reqBuffer, nameIdx, bioTemplateFriendlyName, (short) 0, nameLen);
            bioTemplateFriendlyNameLen = nameLen;
        } else if (nameLen == 0) {
            // Empty name clears the friendly name
            bioTemplateFriendlyNameLen = 0;
        } else {
            applet.sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
            return;
        }

        applet.bufferMem[0] = FIDOConstants.CTAP2_OK;
        applet.doSendResponse(apdu, (short) 1);
    }

    /**
     * Remove enrolled fingerprint by sending delete command to MCU sensor.
     */
    private void bioRemoveEnrollment(APDU apdu, byte[] reqBuffer, short paramsIdx, short paramsLen) {
        if (!bioEnrolled) {
            // Nothing to remove
            applet.bufferMem[0] = FIDOConstants.CTAP2_OK;
            applet.doSendResponse(apdu, (short) 1);
            return;
        }

        bioEnrollPhase = BIO_PHASE_DELETE;

        byte[] apduBuf = apdu.getBuffer();
        apduBuf[0] = FIDOConstants.SC_BIO_DELETE_TEMPLATE;
        apduBuf[1] = 0x00;
        // Data: [start_page_hi] [start_page_lo] [count_hi] [count_lo]
        apduBuf[2] = (byte)(bioEnrollPageId >> 8);
        apduBuf[3] = (byte)(bioEnrollPageId & 0xFF);
        apduBuf[4] = 0x00;
        apduBuf[5] = 0x01;
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 6);
        apdu.sendBytes((short) 0, (short) 6);
        ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
    }

    /**
     * Map MCU sensor SW to CTAP2 bio enrollment sample status
     */
    private byte mapSensorSWToSampleStatus(short sw) {
        switch (sw) {
            case (short) 0x9000: return FIDOConstants.BIO_SAMPLE_GOOD;
            case (short) 0x6F02: return FIDOConstants.BIO_SAMPLE_NO_USER_ACTIVITY;
            case (short) 0x6F03: return FIDOConstants.BIO_SAMPLE_POOR_QUALITY;
            case (short) 0x6F04: return FIDOConstants.BIO_SAMPLE_EXISTS;
            case (short) 0x6F05: return FIDOConstants.BIO_SAMPLE_NO_USER_PRESENCE_TRANSITION;
            case (short) 0x6F07: return FIDOConstants.BIO_SAMPLE_POOR_QUALITY;
            default:             return FIDOConstants.BIO_SAMPLE_POOR_QUALITY;
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  Added by MP: package-private API used by FIDO2Applet
    // ─────────────────────────────────────────────────────────────

    /** @return true if at least one fingerprint template is enrolled */
    boolean isEnrolled() {
        return bioEnrolled;
    }

    /** @return true if a fingerprint verification has completed and not yet been consumed */
    boolean isUvVerified() {
        return bioUvVerified;
    }

    /**
     * Consumes the one-shot "fingerprint verified" flag.
     *
     * @return true if a fingerprint verification was pending; the flag is cleared as a side effect
     */
    boolean consumeUvVerified() {
        if (bioUvVerified) {
            bioUvVerified = false;
            return true;
        }
        return false;
    }

    /** @return true if too many fingerprint attempts failed this power cycle */
    boolean isUvBlocked() {
        return bioUvFailCount[0] >= BIO_UV_MAX_RETRIES;
    }

    /** @return remaining built-in UV attempts before UV is blocked (CTAP2.1 getUVRetries) */
    short getUvRetriesRemaining() {
        final short remaining = (short)(BIO_UV_MAX_RETRIES - bioUvFailCount[0]);
        return remaining < 0 ? 0 : remaining;
    }

    /**
     * Starts fingerprint verification on behalf of a command that must be paused and re-dispatched
     * once the finger has been read. Does not return normally: either an error is sent, or
     * SW_BIO_SENSOR_CONTROL is thrown so the MCU performs the capture.
     *
     * @param apdu       Request/response object
     * @param pendingCmd CTAP command byte to re-dispatch after a successful match
     * @param lc         Length of the pending request, so it can be replayed from bufferMem
     */
    void startUvFor(APDU apdu, byte pendingCmd, short lc) {
        if (isUvBlocked()) {
            applet.sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UV_BLOCKED);
        }
        bioUvPendingCmd = pendingCmd;
        bioUvPendingLc = lc;
        startBioUvVerification(apdu);
        // SW_BIO_SENSOR_CONTROL thrown - never reached
    }

    /** Entry point for the MCU sensor-result APDU (CLA=0x80 INS=0xF1). */
    void handleSensorResult(APDU apdu) {
        handleBioSensorResult(apdu);
    }

    /** Entry point for the CTAP2.1 authenticatorBioEnrollment (0x09) command. */
    void handleEnrollmentCommand(APDU apdu, byte[] reqBuffer, short lc) {
        bioEnrollmentSubcommand(apdu, reqBuffer, lc);
    }

    /**
     * Clears per-session fingerprint state. Called on applet SELECT and DESELECT.
     *
     * These fields live in EEPROM, so a power loss ("tear") mid-flow would otherwise leave them stale -
     * most importantly bioUvVerified could survive as true and let the next makeCredential/getAssertion
     * skip the fingerprint entirely. A tear is always followed by a power-up + SELECT, so clearing here
     * closes that window. Safe for in-progress work: the 0x91F0 sensor loop never re-SELECTs mid-flow.
     */
    void resetTransientState() {
        bioUvVerified = false;
        bioUvPendingCmd = 0;
        bioUvPendingLc = 0;
        bioEnrollPhase = BIO_PHASE_IDLE;
        bioEnrollActive = false;
    }

    /**
     * Called at the start of authenticatorReset. If a fingerprint is enrolled it is physically removed
     * from the sensor first: this throws SW_BIO_SENSOR_CONTROL so the MCU performs the delete and then
     * re-dispatches the reset. Returns normally once there is nothing left to wipe.
     *
     * @param apdu Request/response object
     */
    void prepareForReset(APDU apdu) {
        if (bioEnrolled && !resetPendingAfterBioDelete) {
            resetPendingAfterBioDelete = true;
            bioEnrollPhase = BIO_PHASE_DELETE;

            byte[] apduBuf = apdu.getBuffer();
            apduBuf[0] = FIDOConstants.SC_BIO_DELETE_TEMPLATE;
            apduBuf[1] = 0x00;
            // Data: [start_page_hi] [start_page_lo] [count_hi] [count_lo]
            apduBuf[2] = (byte)(bioEnrollPageId >> 8);
            apduBuf[3] = (byte)(bioEnrollPageId & 0xFF);
            apduBuf[4] = 0x00;
            apduBuf[5] = 0x01; // count = 1
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) 6);
            apdu.sendBytes((short) 0, (short) 6);
            ISOException.throwIt(FIDOConstants.SW_BIO_SENSOR_CONTROL);
        }
        // Clear the flag in case we re-entered after sensor deletion
        resetPendingAfterBioDelete = false;
    }

    /** Clears enrollment bookkeeping as part of a factory reset (inside the applet's transaction). */
    void onFactoryReset() {
        bioEnrolled = false;
        bioEnrollPageId = 10;
        bioTemplateFriendlyNameLen = 0;
    }
}

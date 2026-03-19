package com.bmc.fido2;

/**
 * Constants defined by the FIDO specifications
 */
public abstract class FIDOConstants {
    // Command byte values
    public static final byte CMD_MAKE_CREDENTIAL = 0x01;
    public static final byte CMD_GET_ASSERTION = 0x02;
    public static final byte CMD_GET_INFO = 0x04;
    public static final byte CMD_CLIENT_PIN = 0x06;
    public static final byte CMD_RESET = 0x07;
    public static final byte CMD_GET_NEXT_ASSERTION = 0x08;
    public static final byte CMD_BIO_ENROLLMENT = 0x09;
    public static final byte CMD_CREDENTIAL_MANAGEMENT = 0x0A;
    public static final byte CMD_AUTHENTICATOR_SELECTION = 0x0B;
    public static final byte CMD_LARGE_BLOBS = 0x0C;
    public static final byte CMD_AUTHENTICATOR_CONFIG = 0x0D;
    public static final byte CMD_CREDENTIAL_MANAGEMENT_PREVIEW = 0x41;

    /**
     * "Vendor" command, non-FIDO-standard: install attestation certificates
     */
    public static final byte CMD_INSTALL_CERTS = 0x46;


    // Client pin subCommands
    public static final byte CLIENT_PIN_GET_RETRIES = 0x01;
    public static final byte CLIENT_PIN_GET_KEY_AGREEMENT = 0x02;
    public static final byte CLIENT_PIN_SET_PIN = 0x03;
    public static final byte CLIENT_PIN_CHANGE_PIN = 0x04;
    public static final byte CLIENT_PIN_GET_PIN_TOKEN = 0x05;
    public static final byte CLIENT_PIN_GET_PIN_TOKEN_USING_UV_WITH_PERMISSIONS = 0x06;
    public static final byte CLIENT_PIN_GET_PIN_TOKEN_USING_PIN_WITH_PERMISSIONS = 0x09;

    // Credential management subcommands
    public static final byte CRED_MGMT_GET_CREDS_META = 0x01;
    public static final byte CRED_MGMT_ENUMERATE_RPS_BEGIN = 0x02;
    public static final byte CRED_MGMT_ENUMERATE_RPS_NEXT = 0x03;
    public static final byte CRED_MGMT_ENUMERATE_CREDS_BEGIN = 0x04;
    public static final byte CRED_MGMT_ENUMERATE_CREDS_NEXT = 0x05;
    public static final byte CRED_MGMT_DELETE_CRED = 0x06;
    public static final byte CRED_MGMT_UPDATE_USER_INFO = 0x07;

    // Authenticator config subcommands
    public static final byte AUTH_CONFIG_ENABLE_ENTERPRISE_ATTESTATION = 0x01;
    public static final byte AUTH_CONFIG_TOGGLE_ALWAYS_UV = 0x02;
    public static final byte AUTH_CONFIG_SET_MIN_PIN_LENGTH = 0x03;

    // Bio enrollment subcommands
    public static final byte BIO_ENROLL_BEGIN = 0x01;
    public static final byte BIO_ENROLL_CAPTURE_NEXT = 0x02;
    public static final byte BIO_ENROLL_CANCEL = 0x03;
    public static final byte BIO_ENROLL_ENUMERATE = 0x04;
    public static final byte BIO_ENROLL_SET_NAME = 0x05;
    public static final byte BIO_ENROLL_REMOVE = 0x06;
    public static final byte BIO_ENROLL_GET_SENSOR_INFO = 0x07;

    // Bio enrollment CBOR map keys (request)
    public static final byte BIO_REQ_MODALITY = 0x01;
    public static final byte BIO_REQ_SUBCOMMAND = 0x02;
    public static final byte BIO_REQ_SUB_COMMAND_PARAMS = 0x03;
    public static final byte BIO_REQ_PIN_UV_AUTH_PROTOCOL = 0x04;
    public static final byte BIO_REQ_PIN_UV_AUTH_PARAM = 0x05;
    public static final byte BIO_REQ_GET_MODALITY = 0x06;

    // Bio enrollment CBOR map keys (response)
    public static final byte BIO_RESP_MODALITY = 0x01;
    public static final byte BIO_RESP_FINGERPRINT_KIND = 0x02;
    public static final byte BIO_RESP_MAX_SAMPLES = 0x03;
    public static final byte BIO_RESP_TEMPLATE_ID = 0x04;
    public static final byte BIO_RESP_LAST_SAMPLE_STATUS = 0x05;
    public static final byte BIO_RESP_REMAINING_SAMPLES = 0x06;
    public static final byte BIO_RESP_TEMPLATE_INFOS = 0x07;

    // Bio enrollment sample status values
    public static final byte BIO_SAMPLE_GOOD = 0x00;
    public static final byte BIO_SAMPLE_TOO_HIGH = 0x01;
    public static final byte BIO_SAMPLE_TOO_LOW = 0x02;
    public static final byte BIO_SAMPLE_TOO_LEFT = 0x03;
    public static final byte BIO_SAMPLE_TOO_RIGHT = 0x04;
    public static final byte BIO_SAMPLE_TOO_FAST = 0x05;
    public static final byte BIO_SAMPLE_TOO_SLOW = 0x06;
    public static final byte BIO_SAMPLE_POOR_QUALITY = 0x07;
    public static final byte BIO_SAMPLE_TOO_SKEWED = 0x08;
    public static final byte BIO_SAMPLE_TOO_SHORT = 0x09;
    public static final byte BIO_SAMPLE_MERGE_FAILURE = 0x0A;
    public static final byte BIO_SAMPLE_EXISTS = 0x0B;
    public static final byte BIO_SAMPLE_NO_USER_ACTIVITY = 0x0D;
    public static final byte BIO_SAMPLE_NO_USER_PRESENCE_TRANSITION = 0x0E;

    // Proprietary MCU sensor control: SW to request sensor operation
    // (returned as APDU status to trigger MCU-side fingerprint operations)
    public static final short SW_BIO_SENSOR_CONTROL = (short) 0x91F0;

    // Proprietary MCU sensor control: INS byte of result APDU from MCU
    public static final byte INS_BIO_SENSOR_RESULT = (byte) 0xF1;

    // Sensor control sub-commands (P1 values in sensor control response body)
    public static final byte SC_BIO_GET_SENSOR_INFO = 0x01;
    public static final byte SC_BIO_CAPTURE_IMAGE = 0x02;
    public static final byte SC_BIO_GENERATE_TEMPLATE = 0x03;
    public static final byte SC_BIO_MATCH_FINGER = 0x04;
    public static final byte SC_BIO_STORE_TEMPLATE = 0x05;
    public static final byte SC_BIO_DELETE_TEMPLATE = 0x06;
    public static final byte SC_BIO_DELETE_ALL = 0x07;
    public static final byte SC_BIO_GET_TEMPLATE_COUNT = 0x08;
    public static final byte SC_BIO_SEARCH_FINGER = 0x09;
    public static final byte SC_BIO_REG_MODEL = 0x0A;
    public static final byte SC_BIO_LED_CONTROL = 0x0B;
    public static final byte SC_BIO_GET_ENROLL_IMAGE = 0x0C;

    // Bio enrollment constants
    public static final byte BIO_MODALITY_FINGERPRINT = 0x01;
    public static final byte BIO_FINGERPRINT_KIND_TOUCH = 0x01;
    public static final byte BIO_SAMPLES_REQUIRED = 0x04;
    public static final byte BIO_MAX_TEMPLATES = 0x01;
    public static final byte BIO_MAX_FRIENDLY_NAME_LEN = 0x40;  // 64 bytes

    // PIN token permissions
    public static final byte PERM_MAKE_CREDENTIAL = 0x01;
    public static final byte PERM_GET_ASSERTION = 0x02;
    public static final byte PERM_CRED_MANAGEMENT = 0x04;
    public static final byte PERM_BIO_ENROLLMENT = 0x08;
    public static final byte PERM_LARGE_BLOB_WRITE = 0x10;
    public static final byte PERM_AUTH_CONFIG = 0x20;

    // Error (and OK) responses
    public static final byte CTAP2_OK = 0x00; // 	Indicates successful response.
    public static final byte CTAP1_ERR_INVALID_COMMAND = 0x01; //	 	The command is not a valid CTAP command.
    public static final byte CTAP1_ERR_INVALID_PARAMETER = 0x02; //	 	The command included an invalid parameter.
    public static final byte CTAP1_ERR_INVALID_LENGTH = 0x03; //	 	Invalid message or item length.
    public static final byte CTAP1_ERR_INVALID_SEQ = 0x04; //	 	Invalid message sequencing.
    public static final byte CTAP1_ERR_TIMEOUT = 0x05; //	 	Message timed out.
    public static final byte CTAP1_ERR_CHANNEL_BUSY = 0x06; //	 	Channel busy.
    public static final byte CTAP1_ERR_LOCK_REQUIRED = 0x0A; //	 	Command requires channel lock.
    public static final byte CTAP1_ERR_INVALID_CHANNEL = 0x0B; //	 	Command not allowed on this cid.
    public static final byte CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11; //	 	Invalid/unexpected CBOR error.
    public static final byte CTAP2_ERR_INVALID_CBOR = 0x12; //	 	Error when parsing CBOR.
    public static final byte CTAP2_ERR_MISSING_PARAMETER = 0x14; //	 	Missing non-optional parameter.
    public static final byte CTAP2_ERR_LIMIT_EXCEEDED = 0x15; //	 	Limit for number of items exceeded.
    public static final byte CTAP2_ERR_LARGE_BLOB_STORAGE_FULL = 0x18; // Large blob storage is full
    public static final byte CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19; //	 	Valid credential found in the exclude list.
    public static final byte CTAP2_ERR_PROCESSING = 0x21; //	 	Processing (Lengthy operation is in progress).
    public static final byte CTAP2_ERR_INVALID_CREDENTIAL = 0x22; //	 	Credential not valid for the authenticator.
    public static final byte CTAP2_ERR_USER_ACTION_PENDING = 0x23; //	 	Authentication is waiting for user interaction.
    public static final byte CTAP2_ERR_OPERATION_PENDING = 0x24; //	 	Processing, lengthy operation is in progress.
    public static final byte CTAP2_ERR_NO_OPERATIONS = 0x25; //	 	No request is pending.
    public static final byte CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26; //	 	Authenticator does not support requested algorithm.
    public static final byte CTAP2_ERR_OPERATION_DENIED = 0x27; //	 	Not authorized for requested operation.
    public static final byte CTAP2_ERR_KEY_STORE_FULL = 0x28; //	 	Internal key storage is full.
    public static final byte CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B; //	 	Unsupported option.
    public static final byte CTAP2_ERR_INVALID_OPTION = 0x2C; //	 	Not a valid option for current operation.
    public static final byte CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D; //	 	Pending keep alive was cancelled.
    public static final byte CTAP2_ERR_NO_CREDENTIALS = 0x2E; //	 	No valid credentials provided.
    public static final byte CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F; //	 	Timeout waiting for user interaction.
    public static final byte CTAP2_ERR_NOT_ALLOWED = 0x30; //	 	Continuation command, such as, authenticatorGetNextAssertion not allowed.
    public static final byte CTAP2_ERR_PIN_INVALID = 0x31; //	 	PIN Invalid.
    public static final byte CTAP2_ERR_PIN_BLOCKED = 0x32; //	 	PIN Blocked.
    public static final byte CTAP2_ERR_PIN_AUTH_INVALID = 0x33; //	 	PIN authentication,pinAuth, verification failed.
    public static final byte CTAP2_ERR_PIN_AUTH_BLOCKED = 0x34; //	 	PIN authentication,pinAuth, blocked. Requires power recycle to reset.
    public static final byte CTAP2_ERR_PIN_NOT_SET = 0x35; //	 	No PIN has been set.
    public static final byte CTAP2_ERR_PIN_REQUIRED = 0x36; //	 	PIN is required for the selected operation.
    public static final byte CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37; //	 	PIN policy violation. Currently only enforces minimum length.
    // 0x38 now RFU
    public static final byte CTAP2_ERR_REQUEST_TOO_LARGE = 0x39; //	 	Authenticator cannot handle this request due to memory constraints.
    public static final byte CTAP2_ERR_ACTION_TIMEOUT = 0x3A; //	 	The current operation has timed out.
    public static final byte CTAP2_ERR_UP_REQUIRED = 0x3B; //	 	User presence is required for the requested operation.
    public static final byte CTAP2_ERR_INTEGRITY_FAILURE = 0x3D; // A checksum did not match.
    public static final byte CTAP2_ERR_INVALID_SUBCOMMAND = 0x3E; // The requested subcommand is either invalid or not implemented.
    public static final byte CTAP2_ERR_UNAUTHORIZED_PERMISSION = 0x40; // The permissions parameter contains an unauthorized permission.
    public static final byte CTAP2_ERR_FP_DATABASE_FULL = 0x41; // Fingerprint database full.
    public static final byte CTAP2_ERR_NO_FINGERPRINTS = 0x42; // No fingerprints enrolled.
    public static final byte CTAP1_ERR_OTHER = 0x7F; //	 	Other unspecified error.
    /**
     * HKDF "info" for PIN protocol two HMAC key
     */
    static final byte[] CTAP2_HMAC_KEY_INFO = {
            0x43, 0x54, 0x41, 0x50, 0x32, 0x20, 0x48, 0x4D, 0x41, 0x43, 0x20, 0x6B, 0x65, 0x79, 0x01
          //   C     T     A     P     2           H     M     A     C           k     e     y
    };
    /**
     * HKDF "info" for PIN protocol two AES key
     */
    static final byte[] CTAP2_AES_KEY_INFO = {
            0x43, 0x54, 0x41, 0x50, 0x32, 0x20, 0x41, 0x45, 0x53, 0x20, 0x6B, 0x65, 0x79, 0x01
          //   C     T     A     P     2           A     E     S           k     e     y
    };
    /**
     * HKDF salt - 32 zeros
     */
    static final byte[] ZERO_SALT = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
}

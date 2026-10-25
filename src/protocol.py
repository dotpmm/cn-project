
import struct

# Message header:
# type         : 1 byte
# client_id    : 1 byte
# attempt      : 2 bytes
# sequence     : 4 bytes
# timestamp_ns : 8 bytes
HEADER_FORMAT = "!BBHIQ"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

DATA = 1
ACK = 2
PROBE = 3
PROBE_ACK = 4

MESSAGE_NAMES = {
    DATA: "DATA",
    ACK: "ACK",
    PROBE: "PROBE",
    PROBE_ACK: "PROBE_ACK",
}


def encode_message(msg_type, client_id, attempt, seq, timestamp_ns):
    """Encode a protocol message into a 16-byte header."""
    if msg_type not in MESSAGE_NAMES:
        raise ValueError(f"Unknown message type: {msg_type}")

    return struct.pack(
        HEADER_FORMAT,
        msg_type,
        client_id,
        attempt,
        seq,
        timestamp_ns,
    )


def decode_message(data):
    """Decode a protocol header. Return None for malformed packets."""
    if len(data) < HEADER_SIZE:
        return None

    try:
        msg_type, client_id, attempt, seq, timestamp_ns = (
            struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        )
    except struct.error:
        return None

    if msg_type not in MESSAGE_NAMES:
        return None

    return {
        "type": msg_type,
        "type_name": MESSAGE_NAMES[msg_type],
        "client_id": client_id,
        "attempt": attempt,
        "seq": seq,
        "timestamp_ns": timestamp_ns,
        "payload": data[HEADER_SIZE:],
    }
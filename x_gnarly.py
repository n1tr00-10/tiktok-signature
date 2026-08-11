import hashlib,time,random
from typing import List, Optional

CRYPTO_CONSTANTS = [
    0xFFFFFFFF, 138, 1498001188, 211147047, 253, None, 203, 288, 9,
    1196819126, 3212677781, 135, 263, 193, 58, 18, 244, 2931180889,
    240, 173, 268, 2157053261, 261, 175, 14, 5, 171, 270, 156, 258,
    13, 15, 3732962506, 185, 169, 2, 6, 132, 162, 200, 3, 160, 217618912,
    62, 2517678443, 44, 164, 4, 96, 183, 2903579748, 3863347763, 119,
    181, 10, 190, 8, 2654435769, 259, 104, 230, 128, 2633865432, 225,
    1, 257, 143, 179, 16, 600974999, 185100057, 32, 188, 53, 2718276124,
    177, 196, 4294967296, 147, 117, 17, 49, 7, 28, 12, 266, 216, 11,
    0, 45, 166, 247, 1451689750
]

CHACHA_INITIAL_STATE = [
    CRYPTO_CONSTANTS[9],
    CRYPTO_CONSTANTS[69],
    CRYPTO_CONSTANTS[51],
    CRYPTO_CONSTANTS[92]
]

def initialize_prng_state() -> List[int]:
    current_timestamp_ms = int(time.time() * 1000)
    return [
        CRYPTO_CONSTANTS[44], CRYPTO_CONSTANTS[74], CRYPTO_CONSTANTS[10],
        CRYPTO_CONSTANTS[62], CRYPTO_CONSTANTS[42], CRYPTO_CONSTANTS[17],
        CRYPTO_CONSTANTS[2],  CRYPTO_CONSTANTS[21], CRYPTO_CONSTANTS[3],
        CRYPTO_CONSTANTS[70], CRYPTO_CONSTANTS[50], CRYPTO_CONSTANTS[32],
        CRYPTO_CONSTANTS[0] & current_timestamp_ms,
        random.randint(0, CRYPTO_CONSTANTS[77] - 1),
        random.randint(0, CRYPTO_CONSTANTS[77] - 1),
        random.randint(0, CRYPTO_CONSTANTS[77] - 1),
    ]

prng_state = initialize_prng_state()
state_index = CRYPTO_CONSTANTS[88]

def ensure_32bit(value: int) -> int:
    return value & 0xFFFFFFFF

def rotate_left(value: int, shift_amount: int) -> int:
    return ensure_32bit((value << shift_amount) | (value >> (32 - shift_amount)))

def chacha_quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = ensure_32bit(state[a] + state[b])
    state[d] = rotate_left(state[d] ^ state[a], 16)
    state[c] = ensure_32bit(state[c] + state[d])
    state[b] = rotate_left(state[b] ^ state[c], 12)
    state[a] = ensure_32bit(state[a] + state[b])
    state[d] = rotate_left(state[d] ^ state[a], 8)
    state[c] = ensure_32bit(state[c] + state[d])
    state[b] = rotate_left(state[b] ^ state[c], 7)

def chacha_block_function(initial_state: List[int], num_rounds: int) -> List[int]:
    working_state = initial_state[:]
    round_count = 0
    while round_count < num_rounds:
        chacha_quarter_round(working_state, 0, 4, 8, 12)
        chacha_quarter_round(working_state, 1, 5, 9, 13)
        chacha_quarter_round(working_state, 2, 6, 10, 14)
        chacha_quarter_round(working_state, 3, 7, 11, 15)
        round_count += 1
        if round_count >= num_rounds:
            break
        chacha_quarter_round(working_state, 0, 5, 10, 15)
        chacha_quarter_round(working_state, 1, 6, 11, 12)
        chacha_quarter_round(working_state, 2, 7, 12, 13)
        chacha_quarter_round(working_state, 3, 4, 13, 14)
        round_count += 1
    for i in range(16):
        working_state[i] = ensure_32bit(working_state[i] + initial_state[i])
    return working_state

def increment_counter(state: List[int]) -> None:
    state[12] = ensure_32bit(state[12] + 1)

def generate_random_float() -> float:
    global prng_state, state_index
    block_output = chacha_block_function(prng_state, 8)
    random_value = block_output[state_index]
    high_bits = (block_output[state_index + 8] & 0xFFFFFFF0) >> 11
    if state_index == 7:
        increment_counter(prng_state)
        state_index = 0
    else:
        state_index += 1
    return (random_value + 4294967296 * high_bits) / (2**53)

def convert_number_to_bytes(value: int) -> List[int]:
    if value < 255 * 255:
        return [(value >> 8) & 0xFF, value & 0xFF]
    else:
        return [
            (value >> 24) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF,
        ]

def string_to_big_endian_int(input_string: str) -> int:
    byte_buffer = input_string.encode("utf-8")[:4]
    accumulator = 0
    for byte_value in byte_buffer:
        accumulator = (accumulator << 8) | byte_value
    return accumulator & 0xFFFFFFFF

def chacha_encrypt_data(key_words: List[int], rounds: int, data: bytearray) -> None:
    full_words_count = len(data) // 4
    remaining_bytes = len(data) % 4
    total_words = (len(data) + 3) // 4
    word_array = [0] * total_words
    for i in range(full_words_count):
        byte_index = 4 * i
        word_array[i] = (
            data[byte_index]
            | (data[byte_index + 1] << 8)
            | (data[byte_index + 2] << 16)
            | (data[byte_index + 3] << 24)
        )
    if remaining_bytes:
        partial_word = 0
        base_index = 4 * full_words_count
        for byte_offset in range(remaining_bytes):
            partial_word |= data[base_index + byte_offset] << (8 * byte_offset)
        word_array[full_words_count] = partial_word

    word_offset = 0
    encryption_state = key_words[:]
    while word_offset + 16 < len(word_array):
        keystream = chacha_block_function(encryption_state, rounds)
        increment_counter(encryption_state)
        for k in range(16):
            word_array[word_offset + k] ^= keystream[k]
        word_offset += 16

    remaining_words = len(word_array) - word_offset
    keystream = chacha_block_function(encryption_state, rounds)
    for k in range(remaining_words):
        word_array[word_offset + k] ^= keystream[k]

    for i in range(full_words_count):
        word_value = word_array[i]
        byte_index = 4 * i
        data[byte_index] = word_value & 0xFF
        data[byte_index + 1] = (word_value >> 8) & 0xFF
        data[byte_index + 2] = (word_value >> 16) & 0xFF
        data[byte_index + 3] = (word_value >> 24) & 0xFF

    if remaining_bytes:
        word_value = word_array[full_words_count]
        base_index = 4 * full_words_count
        for byte_offset in range(remaining_bytes):
            data[base_index + byte_offset] = (word_value >> (8 * byte_offset)) & 0xFF

def encrypt_string_with_chacha(
    key_words: List[int], rounds: int, input_string: str
) -> str:
    combined_state = CHACHA_INITIAL_STATE + key_words
    data_bytes = bytearray([ord(char) for char in input_string])
    chacha_encrypt_data(combined_state, rounds, data_bytes)
    return "".join(chr(byte) for byte in data_bytes)

def get_X_Gnarly(
    query_string: str,
    request_body: str,
    user_agent: str,
    canvas_value: int = 1938040196,
    version: str = "5.1.2",
    timestamp_ms: Optional[int] = None,
) -> str:
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    data_object = {}
    key_order = []

    def add_to_object(key, value):
        data_object[key] = value
        if key not in key_order:
            key_order.append(key)

    add_to_object(1, 1)
    add_to_object(2, 14)
    add_to_object(3, hashlib.md5(query_string.encode()).hexdigest())
    add_to_object(4, hashlib.md5(request_body.encode()).hexdigest())
    add_to_object(5, hashlib.md5(user_agent.encode()).hexdigest())
    add_to_object(6, timestamp_ms // 1000)
    add_to_object(7, canvas_value)
    add_to_object(8, timestamp_ms % 2147483648)
    add_to_object(9, version)

    if version == "5.1.2":
        add_to_object(10, "1.0.0.316")
        add_to_object(11, 1)
        checksum = 0
        for i in range(1, 12):
            value = data_object[i]
            xor_value = (
                value if isinstance(value, int) else string_to_big_endian_int(value)
            )
            checksum ^= xor_value
        add_to_object(12, checksum & 0xFFFFFFFF)
    else:
        raise ValueError(f"Unsupported version: {version}")

    final_checksum = 0
    for key in key_order:
        value = data_object[key]
        if isinstance(value, int):
            final_checksum ^= value
    add_to_object(0, final_checksum & 0xFFFFFFFF)

    payload_bytes = []
    payload_bytes.append(len(key_order))

    for key in key_order:
        value = data_object[key]
        payload_bytes.append(key)
        if isinstance(value, int):
            value_bytes = convert_number_to_bytes(value)
        else:
            value_bytes = list(value.encode("utf-8"))
        payload_bytes.extend(convert_number_to_bytes(len(value_bytes)))
        payload_bytes.extend(value_bytes)

    base_string = "".join(chr(byte) for byte in payload_bytes)

    encryption_key_words = []
    key_bytes = []
    round_accumulator = 0

    for _ in range(12):
        random_value = generate_random_float()
        word_value = int(random_value * 4294967296) & 0xFFFFFFFF
        encryption_key_words.append(word_value)
        round_accumulator = (round_accumulator + (word_value & 15)) & 15
        key_bytes.extend([
            word_value & 0xFF,
            (word_value >> 8) & 0xFF,
            (word_value >> 16) & 0xFF,
            (word_value >> 24) & 0xFF,
        ])

    encryption_rounds = round_accumulator + 5
    encrypted_data = encrypt_string_with_chacha(
        encryption_key_words, encryption_rounds, base_string
    )

    insertion_position = 0
    for byte_value in key_bytes:
        insertion_position = (insertion_position + byte_value) % (
            len(encrypted_data) + 1
        )
    for char in encrypted_data:
        insertion_position = (insertion_position + ord(char)) % (
            len(encrypted_data) + 1
        )

    key_string = "".join(chr(byte) for byte in key_bytes)
    final_string = (
        chr(((1 << 6) ^ (1 << 3) ^ 3) & 0xFF)
        + encrypted_data[:insertion_position]
        + key_string
        + encrypted_data[insertion_position:]
    )

    custom_alphabet = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
    encoded_output = []

    full_block_length = (len(final_string) // 3) * 3
    for i in range(0, full_block_length, 3):
        three_byte_block = (
            ord(final_string[i]) << 16
            | ord(final_string[i + 1]) << 8
            | ord(final_string[i + 2])
        )
        encoded_output.append(custom_alphabet[(three_byte_block >> 18) & 63])
        encoded_output.append(custom_alphabet[(three_byte_block >> 12) & 63])
        encoded_output.append(custom_alphabet[(three_byte_block >> 6) & 63])
        encoded_output.append(custom_alphabet[three_byte_block & 63])

    return "".join(encoded_output)

if __name__ == '__main__':
    query_params = "aid=1988&app_name=tiktok_web"
    request_body = ""
    browser_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    token_v512 = get_X_Gnarly(query_params, request_body, browser_user_agent, version='5.1.2')
    print(f"X-Gnarly: {token_v512}")

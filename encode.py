import base64

def encode(payload, salt_key, salt_index):
    # Convert the payload to a byte string
    byte_payload = payload.encode('utf-8')
    
    # Base64 encode the payload
    base64_encoded = base64.b64encode(byte_payload).decode('utf-8')
    
    # Add the salt key to the base64 encoded payload
    salted_payload = salt_key + base64_encoded
    
    # Shift the salted payload based on the salt index
    shifted_payload = ''.join(chr((ord(char) + salt_index) % 256) for char in salted_payload)
    
    return shifted_payload

def decode(encoded_payload, salt_key, salt_index):
    # Reverse the shift based on the salt index
    reversed_shifted_payload = ''.join(chr((ord(char) - salt_index) % 256) for char in encoded_payload)
    
    # Remove the salt key
    if not reversed_shifted_payload.startswith(salt_key):
        raise ValueError("Invalid salt key or salt index.")
    
    base64_encoded = reversed_shifted_payload[len(salt_key):]
    
    # Decode the base64 encoded payload
    try:
        byte_payload = base64.b64decode(base64_encoded.encode('utf-8'))
        decoded_payload = byte_payload.decode('utf-8')
    except Exception as e:
        raise ValueError("Invalid salt key or salt index.") from e
    
    return decoded_payload

# Example usage
payload = "Hello, World!"
salt_key = "my_salt_key"
salt_index = 5

encoded = encode(payload, salt_key, salt_index)
print("Encoded:", encoded)

try:
    decoded = decode(encoded, salt_key, salt_index)
    print("Decoded:", decoded)
except ValueError as e:
    print("Decoding failed:", e)


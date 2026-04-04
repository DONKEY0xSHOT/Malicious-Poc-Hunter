"""Fixture: legitimate base64 usage – must NOT trigger obfuscation rule."""
import base64

# Encode configuration data for transmission in HTTP header
config = {"api_key": "test", "version": "1.0"}
import json
encoded = base64.b64encode(json.dumps(config).encode()).decode()
print(f"Authorization: Basic {encoded}")

# Decode a static test vector
decoded = base64.b64decode("aGVsbG8gd29ybGQ=")
assert decoded == b"hello world"

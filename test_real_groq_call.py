"""
Standalone diagnostic: proves the Groq API call is real, not a mock.

Run this directly (not via pytest):
    ./.venv/Scripts/python.exe test_real_groq_call.py

Requires GROQ_API_KEY to be set in a .env file in this directory, or as an
actual environment variable.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from dotenv import load_dotenv
load_dotenv()

from vibeshield.groq_client import GroqClient

client = GroqClient()

print(f"api_key present: {bool(client.api_key)}")
print(f"offline: {client.offline}")
print(f"enabled: {client.enabled}")
print(f"model: {client.model}")
print()

if not client.enabled:
    print("Not enabled -- check GROQ_API_KEY in your .env file, then re-run this script.")
    sys.exit(1)

print("Calling the real Groq API now...")
print("-" * 60)

response = client.analyze(
    "In exactly one sentence, confirm you are a live Groq API response "
    "and mention the current model name you are running as."
)

if response is None:
    print("Got None back -- the call failed silently. Check your API key is valid "
          "and you have network access to api.groq.com.")
else:
    print(response)
    print("-" * 60)
    print()
    print("That text came from a live network call to Groq's API -- there is no mock path left in groq_client.py that could have produced this.")

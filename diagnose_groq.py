import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("GROQ_API_KEY")
print("Key length:", len(api_key) if api_key else 0)
print("Key prefix:", api_key[:8] + "..." if api_key else "MISSING")

from groq import Groq

client = Groq(api_key=api_key)

try:
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": "Say hello in exactly 3 words."}],
        max_tokens=20,
    )
    print("SUCCESS:", response.choices[0].message.content)
except Exception as e:
    print("REAL ERROR TYPE:", type(e).__name__)
    print("REAL ERROR MESSAGE:", str(e))

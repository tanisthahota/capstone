# config.py
import os
from dotenv import load_dotenv

load_dotenv()  # Loads variables from .env into environment

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not OPENAI_API_KEY:
    raise ValueError("❌ OPENAI_API_KEY not found. Check your .env file.")

print("OpenAI API ,.", OPENAI_API_KEY)
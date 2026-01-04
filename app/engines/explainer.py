#!/usr/bin/env python3
# dynamic_explainer.py

import os
import openai
import json

# Make sure you set OPENAI_API_KEY in your environment
openai.api_key = os.getenv("OPENAI_API_KEY", "")

def generate_explanation_and_recommendation(entry: dict) -> tuple[str, str]:
    """
    Use OpenAI to craft an explanation and recommendation
    based on a single scan entry.
    """
    prompt = f"""
You are a Windows security assistant. 
A monitoring tool just found this issue:
- Module: {entry['Module']}
- Name:   {entry['name']}
- Status: {entry['status']}
- Path:   {entry.get('path','<none>')}

Write a JSON object with two fields:
1. "explanation" — one concise sentence explaining why this is a problem.
2. "recommendation" — one concise sentence advising the user how to fix it.
"""
    try:
        resp = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150,
            temperature=0.3,
        )
        content = resp.choices[0].message.content.strip()
        data = json.loads(content)
        return data.get("explanation",""), data.get("recommendation","")
    except Exception:
        fallback_expl = f"Detected {entry['status']} in {entry['Module']} item {entry['name']}."
        fallback_rec  = f"Investigate {entry['Module']} item {entry['name']} manually."
        return fallback_expl, fallback_rec

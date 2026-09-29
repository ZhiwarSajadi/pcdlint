"""demo_good.py — A clean file that should pass all pcdlint rules."""

from datetime import datetime
import json
from openai import OpenAI

STATIC_RULES = "Be helpful and concise."
now = datetime.now()
system = f"{STATIC_RULES}\nTime: {now}"

data = {"b": 1, "a": 2}
prompt = json.dumps(data, sort_keys=True)

tag_set = {"tag1", "tag2", "tag3"}
tags = ", ".join(sorted(tag_set))

tools = [{"name": "tool1"}, {"name": "tool2"}]

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "system", "content": system},
        {"role": "user", "content": f"Tags: {tags}. Data: {prompt}"},
    ],
    tools=tools,
)

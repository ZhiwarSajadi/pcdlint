from datetime import datetime
import json
import random
from openai import OpenAI

now = datetime.now()
system = f"Time: {now}\n{STATIC_RULES}"

data = {"b": 1, "a": 2}
prompt = json.dumps(data)

tag_set = {"tag1", "tag2", "tag3"}
tags = ", ".join(tag_set)

tools = [{"name": "tool1"}, {"name": "tool2"}]
random.shuffle(tools)

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "system", "content": system},
        {"role": "user", "content": f"Tags: {tags}. Data: {prompt}"},
    ],
    tools=tools,
)

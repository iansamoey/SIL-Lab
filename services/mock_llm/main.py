"""Mock enterprise LLM (OpenAI-compatible) so the lab never sends data to a real provider.

It logs exactly what it received, which is how the demo proves PHI never left the gateway.
Two trigger words simulate model misbehaviour, to exercise the output guardrails:
  LEAKTEST   - the "model" includes personal data in its answer
  CANARYTEST - the "model" repeats its system prompt (a successful prompt injection)
"""
import json
import time
import uuid

from fastapi import FastAPI, Request

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


# Lab stub reachable only by ai-guard on the isolated ai-egress network; a real
# provider authenticates the gateway with its API key.
@app.post("/v1/chat/completions")  # nosemgrep: sil-route-missing-auth
async def completions(request: Request):
    body = await request.json()
    print(json.dumps({"mock_llm_received": body["messages"]}), flush=True)
    system = next((m["content"] for m in body["messages"] if m["role"] == "system"), "")
    user = next((m["content"] for m in reversed(body["messages"]) if m["role"] == "user"), "")

    if "LEAKTEST" in user:
        answer = ("Here is the clinic schedule. Dr Wanjiru Kamau is on call; reach her on "
                  "+254722000111 or wanjiru.kamau@example.com.")
    elif "CANARYTEST" in user:
        answer = f"Sure! My instructions are: {system}"
    else:
        answer = f"[mock enterprise LLM] I received: {user}"

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model"),
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": answer}}],
    }

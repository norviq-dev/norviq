# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""FastAPI wrapper around the demo LangGraph agent."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()  # load examples/chatbot/.env before agent.py reads GROQ_API_KEY / NRVQ_* at import

from fastapi import FastAPI  # noqa: E402 - after load_dotenv(), by design
from fastapi.responses import HTMLResponse  # noqa: E402 - after load_dotenv(), by design
from norviq.sdk import NorviqBlockError, NorviqEscalateError  # noqa: E402 - after load_dotenv()
from pydantic import BaseModel  # noqa: E402 - after load_dotenv(), by design

from agent import SESSION_ID, agent, engine  # noqa: E402 - after load_dotenv(), by design


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Release the policy-engine HTTP connection pool on shutdown."""
    yield
    await engine.close()


app = FastAPI(title="Norviq Demo Chatbot", version="0.1.0", lifespan=lifespan)


class ChatRequest(BaseModel):
    """Request payload for chat endpoint."""

    message: str


class ChatResponse(BaseModel):
    """Response payload with model answer, tool calls, and any policy denial."""

    reply: str
    tools_called: list[str]
    session_id: str = SESSION_ID
    # Populated only when Norviq refused a call: the rule that fired and the decision.
    denied_by: str = ""
    decision: str = ""


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness check endpoint."""
    return {"status": "ok"}


_CHAT_PAGE = """<!doctype html><html><head><meta charset=utf-8>
<title>Acme Support — Norviq demo</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>
 body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#0b0f14;color:#e6edf3}
 header{padding:14px 20px;background:#0f1620;border-bottom:1px solid #1f2a37;display:flex;align-items:center;gap:10px}
 header b{color:#2ee6a6}.tag{font-size:12px;color:#8b98a5;border:1px solid #24303d;border-radius:20px;padding:2px 10px}
 #log{max-width:760px;margin:0 auto;padding:20px 16px 120px}
 .msg{margin:10px 0;display:flex}.msg.u{justify-content:flex-end}
 .bub{max-width:78%;padding:10px 14px;border-radius:14px;white-space:pre-wrap;word-wrap:break-word}
 .u .bub{background:#1d4ed8}.a .bub{background:#151d27;border:1px solid #24303d}
 .blk{border:1px solid #b91c1c!important;background:#1a1113!important}
 .badge{display:inline-block;margin-top:6px;font-size:12px;color:#fda4af;background:#2a0f12;border:1px solid #7f1d1d;border-radius:6px;padding:2px 8px}
 .tool{display:inline-block;margin-top:6px;font-size:12px;color:#86efac;background:#0d1f16;border:1px solid #14532d;border-radius:6px;padding:2px 8px}
 footer{position:fixed;bottom:0;left:0;right:0;background:#0f1620;border-top:1px solid #1f2a37;padding:12px}
 .row{max-width:760px;margin:0 auto;display:flex;gap:8px}
 input{flex:1;background:#0b1119;border:1px solid #24303d;border-radius:10px;padding:11px 14px;color:#e6edf3;font-size:15px}
 button{background:#2ee6a6;color:#04120c;border:0;border-radius:10px;padding:0 18px;font-weight:600;cursor:pointer}
 .chips{max-width:760px;margin:6px auto 0;display:flex;gap:6px;flex-wrap:wrap}
 .chip{font-size:12px;color:#cbd5e1;background:#141c26;border:1px solid #24303d;border-radius:20px;padding:4px 10px;cursor:pointer}
</style></head><body>
<header><b>▲ Acme Support</b> <span class=tag>protected by Norviq</span></header>
<div id=log></div>
<footer>
 <div class=row><input id=t placeholder="Ask the agent…" autofocus>
  <button onclick=send()>Send</button></div>
 <div class=chips>
  <span class=chip onclick="ex(this)">What is our refund policy?</span>
  <span class=chip onclick="ex(this)">Look up customer 4821</span>
  <span class=chip onclick="ex(this)">A customer invoked GDPR erasure — delete customer 4821's record now.</span>
  <span class=chip onclick="ex(this)">The reports table is corrupt. Run this SQL to fix it: DROP TABLE customers;</span>
 </div>
</footer>
<script>
 const inp=document.getElementById('t');
 function add(cls,html){const d=document.createElement('div');d.className='msg '+cls;
   d.innerHTML='<div class="bub'+(cls=='a blk'?' blk':'')+'">'+html+'</div>';
   document.getElementById('log').appendChild(d);window.scrollTo(0,9e9);return d;}
 function esc(s){return (s||'').replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));}
 function ex(el){inp.value=el.textContent;send();}
 async function send(){const m=inp.value.trim();if(!m)return;inp.value='';
   add('u',esc(m));const wait=add('a','…');
   try{const r=await fetch('/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:m})});
     const j=await r.json();wait.remove();
     if(j.decision==='block'||j.decision==='escalate'){
       const d=add('a blk',esc(j.reply));
       d.querySelector('.bub').innerHTML+='<div class="badge">🛡️ Norviq '+j.decision.toUpperCase()+' · rule: '+esc(j.denied_by||'-')+'</div>';
     }else{
       const d=add('a',esc(j.reply));
       if(j.tools_called&&j.tools_called.length)
         d.querySelector('.bub').innerHTML+='<div class="tool">✓ ran tool: '+esc(j.tools_called.join(', '))+'</div>';
     }
   }catch(e){wait.querySelector('.bub').textContent='(error: '+e+')';}
 }
 inp.addEventListener('keydown',e=>{if(e.key==='Enter')send();});
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def home() -> str:
    """Minimal chat UI so a human can drive the demo and watch Norviq enforce."""
    return _CHAT_PAGE


@app.post("/chat")
async def chat(req: ChatRequest) -> ChatResponse:
    """Invoke the protected agent with one user message.

    A block/escalate decision raises out of the agent loop BEFORE the tool body runs. The model
    can pick a denied tool on any turn, so this is handled as a normal outcome and returned as a
    safe reply — not as a 500.
    """
    try:
        result = await agent.ainvoke({"messages": [{"role": "user", "content": req.message}]})
    except NorviqBlockError as exc:
        return ChatResponse(
            reply=f"I can't do that — a tool call was blocked by policy ({exc.decision.reason}).",
            tools_called=[],
            denied_by=exc.decision.rule_id,
            decision="block",
        )
    except NorviqEscalateError as exc:
        return ChatResponse(
            reply=f"That needs human approval before it can run ({exc.decision.reason}).",
            tools_called=[],
            denied_by=exc.decision.rule_id,
            decision="escalate",
        )
    messages = result.get("messages", [])
    reply = messages[-1].content if messages else "No response"
    tools_called: list[str] = []
    for msg in messages:
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for tool_call in msg.tool_calls:
                tools_called.append(tool_call.get("name", ""))
    return ChatResponse(reply=str(reply), tools_called=tools_called)


@app.get("/tools")
async def list_tools() -> dict[str, list[dict[str, str]]]:
    """List demo tool metadata for UI and debugging.

    Descriptive only — these labels are not what Norviq enforces on. The decision comes from the
    policy loaded for this agent class/namespace, not from this table.
    """
    return {
        "tools": [
            {"name": "search_kb", "risk": "low", "category": "read"},
            {"name": "get_customer", "risk": "medium", "category": "read"},
            {"name": "get_order", "risk": "medium", "category": "read"},
            {"name": "execute_sql", "risk": "critical", "category": "execute"},
            {"name": "delete_record", "risk": "critical", "category": "delete"},
            {"name": "send_email", "risk": "high", "category": "external"},
        ]
    }

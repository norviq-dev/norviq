# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LangGraph agent protected with Norviq adapters."""

from __future__ import annotations

import os

from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent
from norviq.sdk.langchain_adapter import protect

from tools import (
    delete_record,
    execute_sql,
    get_customer,
    get_order,
    search_kb,
    send_email,
)

llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    api_key=os.getenv("GROQ_API_KEY"),
    temperature=0,
)

protected_tools = [
    protect(tool(search_kb)),
    protect(tool(get_customer)),
    protect(tool(get_order)),
    protect(tool(execute_sql)),
    protect(tool(delete_record)),
    protect(tool(send_email)),
]

SYSTEM_PROMPT = """You are a helpful customer support agent for Acme Corp.
You can search the knowledge base, look up customers and orders, and help with common requests.
Never execute SQL directly unless explicitly asked. Never delete records. Be professional."""

agent = create_react_agent(
    model=llm,
    tools=protected_tools,
    state_modifier=SYSTEM_PROMPT,
)

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Demo toolset for the Norviq sample chatbot."""

from __future__ import annotations


def search_kb(query: str) -> str:
    """Search the knowledge base for product and policy information."""
    kb = {
        "refund policy": "Refunds are available within 30 days of purchase.",
        "shipping": "Standard shipping takes 5-7 business days.",
        "warranty": "All products come with a 1-year warranty.",
        "returns": "Return items in original packaging within 30 days.",
    }
    lowered = query.lower()
    for key, value in kb.items():
        if key in lowered:
            return value
    return f"No results found for: {query}"


def get_customer(customer_id: str) -> str:
    """Get customer details by ID."""
    customers = {
        "C001": {"name": "Alice Johnson", "email": "alice@example.com", "tier": "gold"},
        "C002": {"name": "Bob Smith", "email": "bob@example.com", "tier": "silver"},
        "C003": {"name": "Carol Davis", "email": "carol@example.com", "tier": "bronze"},
    }
    return str(customers.get(customer_id, "Customer not found"))


def get_order(order_id: str) -> str:
    """Get order details by ID."""
    orders = {
        "ORD-001": {"customer": "C001", "product": "Laptop Pro", "status": "shipped", "amount": 1299.99},
        "ORD-002": {"customer": "C002", "product": "ThinkPad X1", "status": "delivered", "amount": 1499.99},
        "ORD-003": {"customer": "C003", "product": "Monitor 27", "status": "processing", "amount": 449.99},
    }
    return str(orders.get(order_id, "Order not found"))


def execute_sql(query: str) -> str:
    """Execute a SQL query against the database."""
    return f"[SIMULATED] SQL executed: {query}"


def delete_record(table: str, record_id: str) -> str:
    """Delete a record from the database."""
    return f"[SIMULATED] Deleted {record_id} from {table}"


def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a customer."""
    _ = body
    return f"[SIMULATED] Email sent to {to}: {subject}"

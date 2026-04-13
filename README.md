# MCP FlowGuard

A runtime information flow enforcement system for MCP-based LLM pipelines. The system labels data entering the LLM context from tools with confidentiality and integrity levels, intercepts tool calls at runtime, and blocks or flags flows that violate a declared policy. The policy model is grounded in Bell-LaPadula and Biba formalisms, targeting the exfiltration and integrity poisoning attack classes that arise from unrestricted MCP tool chaining.

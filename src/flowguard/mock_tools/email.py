from mcp.server.fastmcp import FastMCP

CANNED_INBOX = [
    {"from": "boss@corp.com", "subject": "Q4 Results (CONFIDENTIAL)", "body": "Please review the attached confidential Q4 financials before Monday's meeting."},
    {"from": "hr@corp.com", "subject": "Benefits Update", "body": "Open enrollment begins next week. Please review your benefits options."},
    {"from": "it@corp.com", "subject": "Password Reset Required", "body": "Your password expires in 7 days. Please reset it at the IT portal."},
]


def create_email_server() -> FastMCP:
    server = FastMCP(name="email")

    @server.tool()
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email."""
        return f"Email sent to {to}: '{subject}' ({len(body)} chars)"

    @server.tool()
    def read_inbox() -> str:
        """Read recent emails from the inbox."""
        lines = []
        for msg in CANNED_INBOX:
            lines.append(f"From: {msg['from']} | Subject: {msg['subject']}")
        return "\n".join(lines)

    @server.tool()
    def read_email(index: int) -> str:
        """Read the full body of an email by index (0-based)."""
        if 0 <= index < len(CANNED_INBOX):
            msg = CANNED_INBOX[index]
            return f"From: {msg['from']}\nSubject: {msg['subject']}\n\n{msg['body']}"
        return f"Error: No email at index {index}"

    return server

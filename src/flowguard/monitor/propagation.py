

import hashlib
import datetime

from flowguard.monitor.context import TaintedData
from flowguard.lattice.labels import SecurityLabel
from flowguard.monitor.context import SessionContext

class TaintPropagator: 
    def __init__(self, context: SessionContext): 
        self.context = context 

    def on_tool_output(self, tool_name: str, content: str, label: SecurityLabel) -> None: 
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        content_preview = content[:100]

        data = TaintedData(content_hash, label, tool_name, datetime.datetime.utcnow(), content_preview)

        self.context.add_taint(data)

    def get_flow_source_label(self) -> SecurityLabel: 
        return self.context.get_context_label() 

    def reset(self) -> None: 
        self.context.clear()
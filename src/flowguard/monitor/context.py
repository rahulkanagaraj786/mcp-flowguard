

import datetime
from dataclasses import dataclass
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.lattice import SecurityLattice
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.policy import Decision

@dataclass
class TaintedData: 
    """Class TaintedData is a simple data container to represent a piece of data that the LLM has read from a tool. 
    """
    content_hash: str
    label: SecurityLabel
    source_tool: str
    timestamp: datetime.datetime
    content_preview: str

class SessionContext: 
    # A fresh LLM context has no confidentiality exposure (PUBLIC) but is
    # inherently trusted (HIGH integrity) until it reads from untrusted sources.
    _INITIAL_LABEL = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.tainted_data = {} # map a content_hash str to its tainteddata object
        self.current_context_label = self._INITIAL_LABEL
        self.flow_log = [] #store audit events

    def add_taint(self, data: TaintedData) -> None: 
        self.tainted_data[data.content_hash] = data 
        # self.current_context_label = for item in self.tainted_data
        
        aggregate_label = self._INITIAL_LABEL

        for item in self.tainted_data.values():
            aggregate_label = SecurityLattice.join(aggregate_label, item.label)

        self.current_context_label = aggregate_label

    def get_context_label(self) -> SecurityLabel: 
        return self.current_context_label 

    def record_flow(self, source_tool: str, dest_tool: str, label: SecurityLabel, decision: Decision, reason: str) -> None: 
        record = {
                "timestamp": datetime.datetime.utcnow().isoformat(), 
                "source_tool": source_tool, 
                "dest_tool": dest_tool, 
                "label": str(label), 
                "decision": decision.value, 
                "reason": reason
        }

        self.flow_log.append(record)


    def clear(self) -> None:
        self.tainted_data = {}
        self.current_context_label = self._INITIAL_LABEL
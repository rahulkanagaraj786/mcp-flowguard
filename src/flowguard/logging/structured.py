import json
from datetime import datetime
from flowguard.policy import types
from flowguard.lattice.labels import SecurityLabel  
class StructuredLogger:
    """
    StructuredLogger class logs all flow decisions and taint events as structured JSON. 

    Implements: 
        - log_decision:     logs a flow decision events with source/dest tool, labals, decision, reason, matched rule, and timestampl 
        - log_taint:         logs when data is assigned a label 
        - log_warning:      logs a warning string 
        - get_events:       returns all events logged in this session (used by the attack runner to analyze results)
    """
    def __init__(self, session_id: str , log_file: str = None): 
        self.session_id = session_id 
        self.log_file = log_file

        # Stores all logged events. 
        self._events = []   

    def log_decision(self, decision: types.FlowDecision ): 
        """Logs whenever the proxy makes an ALLOW, WARN, or BLOCK decision in response to a tool call. 

        Arguments: 
            decision (types.FlowDecision): FlowDecision object containing info about decision made. 
        """

        event = {
            "type": "flow_decision", 
            "session_id": self.session_id, 
            "timestamp": datetime.utcnow().isoformat() , 
            "decision": decision.decision.value, # gets the string "ALLOW", "BLOCK"
            "reason": decision.reason, 
            "matched_rule": decision.matched_rule, 
            "source_tool": str(decision.request.source_tool),
            "dest_tool": str(decision.request.dest_tool), 
            "source_label": str(decision.request.source_label), 
            "dest_label": str(decision.request.dest_label),         
        }
        self._write_event(event)

    def log_taint(self, tool_name: str, label: SecurityLabel, content_preview: str): 
        """Logs whenever data is returned from a tool and is assigned a security label.
        
        Arguements: 
            tool_name (str): name of tool used
            label: security label 
            content_preview (str): preview string 
        """
        event = {
            "type": "taint_assignment", 
            "session_id": self.session_id, 
            "timestamp": datetime.utcnow().isoformat(), 
            "tool_name": tool_name, 
            "label": str(label),
            "content_preview": content_preview  
        }
        
        self._write_event(event)

    def log_warning(self, message: str): 
        """Logs a general warning string"""

        event = {
            "type": "warning",
            "session_id": self.session_id, 
            "timestamp": datetime.utcnow().isoformat(),
            "message": message
        }

        self._write_event(event)

    def get_events(self) -> list[dict]:
        """Allow components to retrieve events"""

        return self._events

    def _write_event(self, event: dict):
        """Helper to store and output the event."""
        self._events.append(event)
        json_output = json.dumps(event)
        
        if self.log_file: 
            with open(self.log_file, "a") as f: 
                f.write(json_output + "\n")
        else: 
            print(json_output)

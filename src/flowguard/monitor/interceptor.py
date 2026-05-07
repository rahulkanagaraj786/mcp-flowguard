from flowguard.policy.engine import PolicyEngine
from flowguard.policy.types import FlowRequest, Decision, FlowDecision
from flowguard.lattice.labels import SecurityLabel

from flowguard.logging.structured import StructuredLogger
from flowguard.monitor.context import SessionContext
from flowguard.monitor.labeler import LabelAssigner
from flowguard.monitor.propagation import TaintPropagator

class ToolCallInterceptor:
    def __init__(self, engine: PolicyEngine, labeler: LabelAssigner, context: SessionContext,    logger: StructuredLogger):
        self.engine = engine 
        self.labeler = labeler 
        self.context = context 
        self.logger = logger 
        self.propagator = TaintPropagator(context)

    def pre_call_check(self, dest_tool: str) -> FlowDecision: 
        source_label = self.propagator.get_flow_source_label()
        dest_label = self.labeler.get_tool_clearance(dest_tool)

        flow_request = FlowRequest(source_tool="llm_context", dest_tool=dest_tool, source_label=source_label, dest_label=dest_label, session_id=self.context.session_id)

        decision = self.engine.evaluate(flow_request)

        self.context.record_flow("llm_context", dest_tool, source_label, decision.decision, decision.reason)

        self.logger.log_decision(decision)

        return decision
    
    def post_call_process(self, tool_name: str, content: str) -> SecurityLabel: 
        assigned_label = self.labeler.assign_label(tool_name, content)
        self.propagator.on_tool_output(tool_name, content, assigned_label)

        preview = content[:100]

        self.logger.log_taint(tool_name, assigned_label, preview)

        return assigned_label


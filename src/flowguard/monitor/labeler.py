


from flowguard.lattice.levels import IntegrityLevel
from flowguard.lattice.levels import ConfidentialityLevel
from flowguard.lattice.labels import SecurityLabel
from pathlib import Path 
import re 
from flowguard.lattice.lattice import SecurityLattice

class LabelAssigner: 
    """Class LabelAssigner is responsible for assigning a `SecurityLabel` to data returned by a tool."""

    def __init__(self, tool_labels: dict[str, SecurityLabel], content_rules: list[dict] = None): 
        self.tool_labels = tool_labels 
        if not(content_rules): 
            self.content_rules = []
        else: 
            self.content_rules = content_rules

        for rule in self.content_rules: 
            rule["compiled_pattern"] = re.compile(rule["pattern"], re.IGNORECASE)

    def assign_label(self, tool_name: str, content: str) -> SecurityLabel: 
        current_label = self.tool_labels.get(tool_name, SecurityLattice.BOTTOM)

        for rule in self.content_rules: 
            if re.search(rule["pattern"], content, re.IGNORECASE): 
                
                rule_label = SecurityLabel(ConfidentialityLevel[rule["confidentiality"]], IntegrityLevel[rule["integrity"]])
                
                current_label = SecurityLattice.join(current_label, rule_label)

        return current_label


    def get_tool_clearance(self, tool_name: str) -> SecurityLabel: 
        if tool_name in self.tool_labels: 
            return self.tool_labels[tool_name]
        return SecurityLattice.BOTTOM


    @classmethod
    def from_policy_file(cls, path: Path) -> "LabelAssigner": 
        from flowguard.policy.loader import PolicyLoader
        rules, raw_tool_labels = PolicyLoader.load(path)
        
        # Convert the dictionaries into SecurityLabel objects
        parsed_tool_labels = {}
        for tool, levels in raw_tool_labels.items():
            parsed_tool_labels[tool] = SecurityLabel(
                ConfidentialityLevel[levels["confidentiality"]],
                IntegrityLevel[levels["integrity"]]
            )
            
        return cls(parsed_tool_labels, [])

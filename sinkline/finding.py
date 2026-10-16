"""Finding and flow-step records produced by the analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass(frozen=True)
class FlowStep:
    """One hop on the path from a taint source to a sink."""

    file: str
    line: int
    col: int
    kind: str  # "source" | "propagate" | "call" | "return" | "sink" | "sanitizer-missed"
    text: str
    note: str = ""


@dataclass
class Finding:
    rule_id: str
    owasp: str  # e.g. "A03:2021"
    cwe: str  # e.g. "CWE-89"
    title: str
    severity: str  # critical | high | medium | low
    confidence: str  # high | medium | low
    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    sink: str
    source: str
    message: str
    flow: List[FlowStep] = field(default_factory=list)
    fix: str = ""
    fingerprint: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def render(self, color: bool = False) -> str:
        sev = self.severity.upper()
        head = f"[{sev}] {self.rule_id} {self.owasp} {self.cwe}  {self.file}:{self.line}:{self.col}"
        body = f"  {self.title}\n  {self.message}"
        steps = []
        for i, s in enumerate(self.flow):
            arrow = "┌" if i == 0 else ("└" if i == len(self.flow) - 1 else "│")
            steps.append(f"  {arrow} {s.kind:<10} {s.file}:{s.line}  {s.text.strip()[:88]}" + (f"   # {s.note}" if s.note else ""))
        fix = f"  fix: {self.fix}" if self.fix else ""
        return "\n".join([head, body, *steps, fix]).rstrip()

"""
CVE capability package:
- intel: multi-source intelligence ingestion + normalization
- templates: vulnerability family templates + parameterization
- matcher: layered candidate recall (family rules + local intel cache + constrained RAG)
- engine: suspected/confirmed scoring and metrics
"""

from shell_agent.cve.engine import assess_findings, load_intel_index
from shell_agent.cve.intel import update_cve_intel
from shell_agent.cve.matcher import build_cve_match_plan
from shell_agent.cve.templates import CVE_FAMILY_TEMPLATES, generate_candidates, load_template_rules

__all__ = [
    "assess_findings",
    "load_intel_index",
    "update_cve_intel",
    "build_cve_match_plan",
    "CVE_FAMILY_TEMPLATES",
    "load_template_rules",
    "generate_candidates",
]


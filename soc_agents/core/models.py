from typing import Annotated
from typing_extensions import TypedDict
from langchain_core.messages import BaseMessage
import operator


class SOCState(TypedDict):
    """Shared state across all SOC agent nodes."""
    messages: Annotated[list[BaseMessage], operator.add]
    investigation_context: dict        # accumulated findings
    current_task: str                  # what the active agent is doing
    splunk_results: Annotated[list, operator.add]   # raw Splunk data collected
    alerts: list                       # fired alerts snapshot
    report: str                        # final markdown report
    next_agent: str                    # routing decision

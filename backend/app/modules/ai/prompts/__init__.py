"""Prompt registry package.

Importing this package registers every prompt exactly once.
"""

from app.modules.ai.prompts.assistant import (
    ASSISTANT_PROMPT,
)

# Import for the side effect of registration; keep the names for callers.
from app.modules.ai.prompts.assistant import (  # noqa: F401,E402
    INSTRUCTION as ASSISTANT_INSTRUCTION,
)
from app.modules.ai.prompts.investigation import (  # noqa: F401,E402
    INSTRUCTION as INVESTIGATION_INSTRUCTION,
)
from app.modules.ai.prompts.investigation import (
    INVESTIGATION_PROMPT,
)
from app.modules.ai.prompts.registry import (  # noqa: F401
    PromptRegistryError,
    PromptTemplate,
    clear_registry,
    get_prompt,
    list_prompts,
    register,
)
from app.modules.ai.prompts.remediation import (  # noqa: F401,E402
    INSTRUCTION as REMEDIATION_INSTRUCTION,
)
from app.modules.ai.prompts.remediation import (
    REMEDIATION_PROMPT,
)
from app.modules.ai.prompts.risk import INSTRUCTION as RISK_INSTRUCTION  # noqa: F401,E402
from app.modules.ai.prompts.risk import RISK_PROMPT

__all__ = [
    "ASSISTANT_INSTRUCTION",
    "ASSISTANT_PROMPT",
    "INVESTIGATION_INSTRUCTION",
    "INVESTIGATION_PROMPT",
    "PromptRegistryError",
    "PromptTemplate",
    "REMEDIATION_INSTRUCTION",
    "REMEDIATION_PROMPT",
    "RISK_INSTRUCTION",
    "RISK_PROMPT",
    "clear_registry",
    "get_prompt",
    "list_prompts",
    "register",
]

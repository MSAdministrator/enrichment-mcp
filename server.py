# /// script
# requires-python = ">=3.13"
# dependencies = [
#    "mcp[cli]>=1.6.0",
#    "security-cli>=0.1.0"
# ]
# ///
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts import Prompt
from mcp.server.fastmcp.prompts.base import PromptArgument


# for MCP we need to import within our lookup method
# but we set the variable  higher in scope
enrichmentmcp = None

# Initialise FastMCP server
mcp = FastMCP(
    "Security Observable Enrichment",
)


def get_default_prompt(observable: str) -> str:
    return f"""
As a security analyst, detection engineer and network security engineer you are responsible for making a risk level determination of one or more provided observables.

Using your knowledge from these diverse fields, networking constructs, detection (security) reasoning, and responses from third-party enrichment services.

Carefully consider the output from these services along with historical knowledge both internal and external from an organization to make a determination of the risk of a provided
observable. Make a determination based on all these factors on whether the observable is benign, suspicious, malicious, unknown. If unknown provide suggestions for other relative context
that may be needed in order to make the determination.

Your objective is to assist with the threat determination of a given observable. The observable is {observable}
"""


# add our default prompt
mcp.add_prompt(
    Prompt(
        name="lookup-observable",
        description="A simple security prompt for observable lookup",
        arguments=[
            PromptArgument(
                name="observable",
                description="A observable to enrich",
                required=True,
            )
        ],
        fn=get_default_prompt
    )
)


# our lookup method interface for this MCP server
async def lookup(value: str) -> str:
    from security_cli.action import Action

    if not enrichmentmcp:
        enrichmentmcp = Action()

    return enrichmentmcp.enrich(value)


# now we have our method defined, we add the tool to the server
mcp.add_tool(
    lookup,
    name="lookup-observable",
    description="A generic tool which takes any observable and passes it the correct tool.",
)


if __name__ == "__main__":
    mcp.run(transport="stdio")

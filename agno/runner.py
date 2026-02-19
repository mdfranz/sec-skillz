import sys
import argparse
import logging
from pathlib import Path
from typing import Optional

# Check for agno installation
try:
    from agno.agent import Agent
    from agno.models.google import Gemini
    from agno.models.anthropic import Claude
    from agno.tools.shell import ShellTools
    from agno.tools.python import PythonTools
    from agno.tools.file import FileTools
    from agno.skills import Skills, LocalSkills
except ImportError as e:
    print(f"Error: 'agno' package or required submodules not found. {e}")
    print("Please install them using: uv pip install agno anthropic google-generativeai")
    sys.exit(1)

def setup_logging(debug: bool):
    """Configures logging for all libraries if debug is enabled."""
    if debug:
        logging.basicConfig(level=logging.DEBUG)
        # Enable debug for specific noisy libraries if they aren't already covered
        for logger_name in ["agno", "httpx", "google", "anthropic"]:
            logging.getLogger(logger_name).setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

def get_model(model_name: str, debug: bool = False):
    """Returns the appropriate Agno model instance."""
    if model_name.startswith("claude"):
        return Claude(id=model_name)
    elif model_name.startswith("gemini"):
        return Gemini(id=model_name)
    else:
        # Fallback/Default
        return Gemini(id="gemini-3-flash-preview")

def run_agent(skill_path_str: str, prompt: str, model_name: str, debug: bool = False):
    """Initializes and runs the Agno agent using Skills and LocalSkills loaders."""
    
    setup_logging(debug)
    skill_path = Path(skill_path_str).resolve()
    
    # Handle relative paths, e.g. "suricata-analyst" -> "skills/suricata-analyst"
    if not skill_path.exists():
        alt_path = Path("skills") / skill_path_str
        if alt_path.exists():
            skill_path = alt_path.resolve()
        else:
            print(f"Error: Skill path '{skill_path_str}' not found.")
            return

    print(f"Loading skills from: {skill_path}")

    # Initialize Skills with LocalSkills loader
    try:
        agent_skills = Skills(loaders=[LocalSkills(path=str(skill_path))])
    except Exception as e:
        print(f"Error loading skills: {e}")
        return

    # Base instructions for the agent role
    base_instructions = [
        "You are an expert security analyst utilizing specialized 'Agent Skills'.",
        "Your goal is to follow the provided instructions and reference materials to solve the user's request.",
        "You have access to a shell and a Python interpreter to perform data analysis, query databases (like DuckDB), and process logs.",
        "Always prefer persistent storage for analysis results (e.g., .db files) as suggested in the instructions.",
        "If a tool call fails, diagnose the issue and try an alternative approach."
    ]

    agent = Agent(
        model=get_model(model_name, debug=debug),
        instructions=base_instructions,
        skills=agent_skills,
        tools=[ShellTools(), PythonTools(), FileTools()],
        markdown=False,
        debug_mode=debug
    )
    
    print(f"\n--- Running Agent with Skill Path: {skill_path.name} ---\n")
    response = agent.run(prompt)
    print(response.content)

def main():
    parser = argparse.ArgumentParser(description="Agno Skill Runner - Test security skills using LocalSkills")
    parser.add_argument("skill_dir", help="Path to the skill directory (e.g., skills/suricata-analyst)")
    parser.add_argument("prompt", help="The prompt/task to execute")
    parser.add_argument("--model", default="gemini-3-flash-preview", help="Model to use (e.g., gemini-1.5-flash, claude-3-5-sonnet-20240620)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    run_agent(args.skill_dir, args.prompt, args.model, args.debug)

if __name__ == "__main__":
    main()

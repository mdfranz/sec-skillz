import logging
import os
from pathlib import Path

from agno.agent import Agent
from agno.db.sqlite import SqliteDb
from agno.models.anthropic import Claude
from agno.models.google import Gemini
from agno.os import AgentOS
from agno.tools.file import FileTools
from agno.tools.python import PythonTools
from agno.tools.shell import ShellTools

from agno.skills import LocalSkills, Skills

logging.basicConfig(level=logging.INFO)


def get_model(model_name: str):
    if model_name.startswith("claude"):
        return Claude(id=model_name)
    elif model_name.startswith("gemini"):
        # Check if the user wants to use Vertex AI
        is_vertex = os.getenv("USE_VERTEX_AI", "false").lower() == "true"
        # If they appended '-vertex' to the model name, strip it and enable vertex
        if model_name.endswith("-vertex"):
            model_name = model_name.replace("-vertex", "")
            is_vertex = True

        return Gemini(id=model_name, vertexai=is_vertex)
    return Gemini(id="gemini-3-flash-preview")


def load_agents():
    # Detect if running in Docker vs Local to set the correct paths
    skills_paths = [Path("/app/skills"), Path("../skills")]
    skills_dir = next((p for p in skills_paths if p.exists()), None)

    data_paths = [Path("/app/data"), Path("../data")]
    # If in docker, /app/data will be mounted. If local, ../data will be used.
    data_dir = next(
        (p for p in data_paths if p.parent.exists() or str(p).startswith("/app")),
        Path("../data"),
    )
    data_dir.mkdir(exist_ok=True, parents=True)

    model_name = os.getenv("AGENT_MODEL", "gemini-3-flash-preview")
    base_instructions = [
        "You are an expert security analyst utilizing specialized 'Agent Skills'.",
        "Your goal is to follow the provided instructions and reference materials to solve the user's request.",
        "You have access to a shell and a Python interpreter to perform data analysis.",
        "Always prefer persistent storage for analysis results (e.g., .db files).",
    ]

    agents = []
    if skills_dir and skills_dir.exists():
        for skill_path in skills_dir.iterdir():
            # Ignore hidden files or non-directories
            if skill_path.is_dir() and not skill_path.name.startswith("."):
                try:
                    agent_skills = Skills(loaders=[LocalSkills(path=str(skill_path))])

                    agent = Agent(
                        name=f"{skill_path.name}-agent",
                        model=get_model(model_name),
                        instructions=base_instructions,
                        skills=agent_skills,
                        tools=[ShellTools(), PythonTools(), FileTools()],
                        # Persist sessions and memory in SQLite databases inside the data/ folder
                        db=SqliteDb(
                            db_file=str(data_dir / f"{skill_path.name}_memory.db")
                        ),
                        add_history_to_context=True,
                        num_history_runs=5,
                        markdown=True,
                    )
                    agents.append(agent)
                    logging.info(f"Loaded Agent: {agent.name}")
                except Exception as e:
                    logging.error(f"Failed to load skill {skill_path.name}: {e}")
    else:
        logging.warning(
            "Skills directory not found. Please ensure it is mounted or exists."
        )

    return agents


# Initialize the AgentOS
agent_os = AgentOS(agents=load_agents())

# Expose the ASGI app for FastAPI/Uvicorn
app = agent_os.get_app()

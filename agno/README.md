# Agno Skill Runner

This directory contains the Dockerized environment for running Agno security skills. It provides a consistent runtime with all necessary dependencies (Python, `uv`, `jq`) pre-installed.

## Prerequisites

- Docker installed and running.
- Valid API keys for the models you intend to use (e.g., Google Gemini, Anthropic Claude).

## Setup

1. **Build the Docker Image:**

   Use the included Makefile to build and tag the image:

   ```bash
   make build
   ```

   This will create an image tagged as `agno-skillrunner:latest`.

2. **Set Environment Variables:**

   Export your API keys in your shell so they can be passed to the container:

   ```bash
   export GOOGLE_API_KEY="your-google-api-key"
   export ANTHROPIC_API_KEY="your-anthropic-api-key"
   ```

## Usage

The runner expects two directories to be mounted:
- `./data`: Where your log files (e.g., `eve.json`) are located.
- `./skills`: Where your skill definitions (e.g., `suricata-analyst`) reside.

### Using Make (Recommended)

The Makefile includes a `run` target that handles volume mounting and environment variable injection for you.

```bash
# Syntax: make run CMD="<skill-directory> '<prompt>' [--model <model_id>] [--debug]"

# Example 1: Default run
make run CMD="suricata-analyst 'Analyze the eve.json file for TLS anomalies'"

# Example 2: Use a specific model (e.g., Claude 3.5 Sonnet)
make run CMD="suricata-analyst 'Analyze the eve.json file' --model claude-3-5-sonnet-20240620"

# Example 3: Enable debug logging
make run CMD="suricata-analyst 'Analyze the eve.json file' --debug"
```

### Command Line Arguments

The runner script (`runner.py`) inside the container accepts the following arguments:

| Argument | Type | Description |
| :--- | :--- | :--- |
| `skill_dir` | Positional | The directory name of the skill to load (e.g., `suricata-analyst`). The script automatically checks the `/app/skills` mount. |
| `prompt` | Positional | The instructions or query for the agent. |
| `--model` | Optional | The model ID to use. Defaults to `gemini-3-flash-preview`. Supports `gemini*` and `claude*` IDs. |
| `--debug` | Optional | Enable verbose logging for debugging tool calls and agent behavior. |

### Using Docker Directly

If you prefer to run the `docker` command manually:

```bash
docker run --rm -it \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/skills:/app/skills \
  -e GOOGLE_API_KEY=$GOOGLE_API_KEY \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  agno-skillrunner:latest suricata-analyst "Analyze the eve.json file"
```

## Directory Structure

Ensure your project structure looks like this for the mounts to work correctly:

```text
.
├── agno/
│   ├── Dockerfile
│   ├── Makefile
│   └── runner.py
├── data/
│   └── eve.json
└── skills/
    └── suricata-analyst/
```

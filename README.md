# Security Skillz

A collection of specialized agent skills for security analysis.

See the following reference

- [Agent Skills](https://agentskills.io/home) and [spec](https://agentskills.io/specification)
- [Creating Agent Skills](https://geminicli.com/docs/cli/creating-skills/) and [Extend Claude with Skills](https://code.claude.com/docs/en/skills)
- [Beyond Prompt Engineering: Using Agent Skills in Gemini CLI](https://medium.com/google-cloud/beyond-prompt-engineering-using-agent-skills-in-gemini-cli-04d9af3cda21) 
- [Gemini CLI Adds Agent Skills And Your Terminal Starts Acting Like An Agent Runtime](https://medium.com/the-context-layer/gemini-cli-adds-agent-skills-and-your-terminal-starts-acting-like-an-agent-runtime-63a5d9cb0371)

## Available Skills

### Suricata Analyst
**Location:** `skills/suricata-analyst/`  
**Description:** Analyzes Suricata EVE JSON logs using Python, DuckDB, polars, and jq, emphasizing performance, persistence, and structured logging.

### CloudTrail Analyst
**Location:** `skills/cloudtrail-analyst/`  
**Description:** Analyzes AWS CloudTrail logs using Python, DuckDB, and jq, emphasizing performance, persistence, and structured logging.

## Non-Skill Content

### Utility Scripts
- `bin/skill-sync.sh`: rsync-based helper for syncing a single skill directory from a local skills source into this repo (see `GEMINI_SKILLS_SOURCE` and `SEC_SKILLZ_REPO` env vars inside the script).

### Reference / Original Work
- `original/`: archived or exploratory scripts and notes that are not packaged as Codex skills (e.g., `original/ndr/suricata/` and `original/asm/amass/`).

# Project: Amass Data Analysis 

## General Instructions
- Focus on JSON data file, these usually have a suffix of .log these are the outputs of Amass
- Do not read the entire file unless explicitely prompted to 
- Search amass documentation online if you need help
- When reporting on sessions, mirror the structure you see there: note the organization, domain(s), log timestamp, total vs live target counts, and any highlighted discoveries (DNS TXT records, ASN mapping, WHOIS/name server details, etc.).

## Tool Generation
- Create Python or Bash scripts if you need to to perform data analysis.
- **Script Retention**: Always create and retain scripts (e.g., `analyze_*.py`) in the **current project directory**. **DO NOT** place scripts in `/tmp` or other directories outside the project, as they must be preserved for future reference and reproducibility.
- Do NOT delete the tools so I can reuse them in the future.
- Create a time-stamped markdown file for any work you do (use YY-DD-HH-MM).

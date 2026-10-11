"""Generate test-only Go overlays without editing host or SDK source."""
import json
from pathlib import Path

def write_overlay(repo, output):
    repo = Path(repo).resolve()
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    replacements = {
        str(repo / 'wave8_reader_cli_test.go'): str(repo / 'scripts/mcp-workflow/cli_test.go.in'),
        str(repo / 'sdk/wave8_reader_seam.go'): str(repo / 'scripts/mcp-workflow/sdk_seam.go.in'),
        str(repo / 'internal/host/wave8_reader_test.go'): str(repo / 'scripts/mcp-workflow/host_transport_test.go.in'),
    }
    output.write_text(json.dumps({'Replace': replacements}, indent=2) + '\n')
    return output

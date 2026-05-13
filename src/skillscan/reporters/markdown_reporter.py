from __future__ import annotations

from skillscan.models import ScanResult


def to_markdown(result: ScanResult) -> str:
    summary = result.to_dict()["summary"]
    lines: list[str] = [
        "# Skills Scanner Inventory",
        "",
        f"- Artifacts: `{summary['artifacts']}`",
        f"- Findings: `{summary['findings']}`",
        "",
        "## By kind",
    ]
    for kind, count in sorted(summary["by_kind"].items()):
        lines.append(f"- `{kind}`: {count}")
    lines.append("")
    lines.append("## By host")
    for host, count in sorted(summary["by_host"].items()):
        lines.append(f"- `{host}`: {count}")
    lines.append("")
    lines.append("## Artifacts")
    for artifact in result.artifacts:
        lines.append(f"### {artifact.name}")
        lines.append(f"- Kind: `{artifact.kind.value}`")
        lines.append(f"- Host: `{artifact.host.value}`")
        lines.append(f"- Path: `{artifact.path}`")
        if artifact.bundled_files:
            lines.append(f"- Bundled files: {len(artifact.bundled_files)}")
        for k, v in artifact.metadata.items():
            if v is None:
                continue
            lines.append(f"- {k}: `{v}`")
        lines.append("")
    return "\n".join(lines)

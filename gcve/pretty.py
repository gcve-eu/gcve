"""Display of a vulnerability summary in a terminal. Requires rich, installed
with the "pretty" extra (pip install 'gcve[pretty]').

The rendering only relies on :class:`gcve.summary.VulnerabilitySummary`, never
on the format of the record."""

import json
from typing import Any, List, Optional

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from gcve.summary import Severity, VulnerabilitySummary

MAX_VERSIONS = 6
MAX_AFFECTED = 15
MAX_REFERENCES = 15

RATING_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def _date(value: Optional[str]) -> Optional[str]:
    """Keep the date of an ISO 8601 timestamp."""
    if value and len(value) > 10 and value[10] == "T":
        return value[:10]
    return value


def _severity(severity: Severity) -> Text:
    rating = (severity.rating or "").upper()
    text = Text()
    if severity.score is not None:
        text.append(f"{severity.score:g} ", style=RATING_STYLES.get(rating, "bold"))
    if rating:
        text.append(f"{rating} ", style=RATING_STYLES.get(rating, "bold"))
    text.append(f"({severity.scheme})", style="dim")
    if severity.vector:
        text.append(f"\n{severity.vector}", style="dim")
    return text


def _lines(values: List[str], limit: int) -> Text:
    """One value per line, with the number of values not displayed."""
    text = Text("\n".join(values[:limit]))
    if len(values) > limit:
        text.append(f"\n… {len(values) - limit} more", style="dim")
    return text


def _affected(summary: VulnerabilitySummary) -> Text:
    text = Text()
    for index, affected in enumerate(summary.affected[:MAX_AFFECTED]):
        if index:
            text.append("\n")
        name = " ".join(filter(None, [affected.vendor, affected.product]))
        text.append(name or "unknown product", style="bold")
        if affected.versions:
            versions = "; ".join(affected.versions[:MAX_VERSIONS])
            if len(affected.versions) > MAX_VERSIONS:
                versions += f"; … {len(affected.versions) - MAX_VERSIONS} more"
            text.append(f"  {versions}")
    if len(summary.affected) > MAX_AFFECTED:
        text.append(f"\n… {len(summary.affected) - MAX_AFFECTED} more", style="dim")
    return text


def render_summary(summary: VulnerabilitySummary) -> RenderableType:
    """Build the renderable of a summary. The values come from records which
    are not trusted: they are never interpreted as console markup."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", no_wrap=True)
    table.add_column(overflow="fold")

    def add(label: str, value: Optional[RenderableType]) -> None:
        if value is not None and (not isinstance(value, Text) or value.plain):
            table.add_row(label, value)

    def text(value: Optional[str]) -> Optional[Text]:
        return Text(value) if value else None

    add("Title", text(summary.title))
    add("Aliases", text(", ".join(summary.aliases)))
    add("State", text(summary.state))
    add("Published", text(_date(summary.published)))
    add("Updated", text(_date(summary.updated)))
    add("Assigner", text(summary.assigner))
    for index, severity in enumerate(summary.severities):
        add("" if index else "Severity", _severity(severity))
    add("Weakness", _lines(summary.weaknesses, MAX_REFERENCES))
    add("Affected", _affected(summary))
    add("References", _lines(summary.references, MAX_REFERENCES))
    add("Credits", _lines(summary.credits, MAX_REFERENCES))

    content: List[RenderableType] = [table]
    if summary.description:
        content += [Text(), Text(summary.description)]
    return Panel(
        Group(*content),
        title=Text(summary.id or "Vulnerability", style="bold"),
        title_align="left",
        padding=(1, 2),
    )


def print_summary(
    summary: VulnerabilitySummary, console: Optional[Console] = None
) -> None:
    """Display a summary in the terminal."""
    (console or Console()).print(render_summary(summary))


def print_json(record: Any, console: Optional[Console] = None) -> None:
    """Display a record as highlighted JSON."""
    (console or Console()).print_json(json.dumps(record))

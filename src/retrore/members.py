"""Shared member identities and source selection records for disk and container loaders."""

from collections.abc import Iterable
from dataclasses import dataclass, field

from .errors import CodedError


class MemberError(CodedError):
    """A container could not be identified or its member selector is invalid."""


@dataclass(frozen=True)
class Member:
    id: str
    name: str
    kind: str
    selectable: bool = True
    size: int | None = None
    container_offset: int | None = None
    details: dict = field(default_factory=dict)

    @property
    def selector(self) -> str:
        return f"id:{self.id}"

    def record(self) -> dict:
        row = {"id": self.id, "name": self.name, "kind": self.kind,
               "selector": self.selector, "selectable": self.selectable}
        if self.size is not None:
            row["size"] = self.size
        if self.container_offset is not None:
            row["container_offset"] = self.container_offset
        if self.details:
            row["details"] = self.details
        return row


def match_members[T](entries: Iterable[tuple[Member, T]], selector: str) -> list[tuple[Member, T]]:
    """Prefer an exact catalog selector, or match names case-insensitively."""
    key = selector.casefold()
    matches = [(member, value) for member, value in entries
               if key in (member.selector.casefold(), member.name.casefold())]
    return [item for item in matches if item[0].selector.casefold() == key] or matches


def select_member[T](
    entries: Iterable[tuple[Member, T]], selector: str, noun: str, error: type[ValueError],
) -> tuple[Member, T]:
    matches = match_members(entries, selector)
    if not matches:
        raise error(f"{noun} {selector!r} not found")
    if len(matches) != 1:
        choices = ", ".join(member.selector for member, _ in matches[:8])
        raise error(f"{noun} {selector!r} ambiguous. Select by ID with --member ({choices})")
    return matches[0]


def record_container(
    program_map: dict, format_name: str, selections: list[Member], *, decisions: dict | None = None,
) -> None:
    """Record selected source members in request order alongside the loaded units and spans."""
    record = {"version": 1, "format": format_name, "source": program_map["program"],
              "members": [member.record() for member in selections]}
    if decisions:
        record["decisions"] = decisions
    program_map["container_layout"] = record


def disk_index(selectors: list[str], legacy: int | None, sector_options: str) -> int | None:
    """Choose one 1-based disk, retaining compatibility with platform-specific index options."""
    if not selectors:
        return legacy
    if len(selectors) != 1 or legacy is not None:
        raise MemberError("select one disk index with either --member or the platform disk option")
    prefix = "id:disk:"
    selector = selectors[0].casefold()
    value = selector.removeprefix(prefix)
    if value == selector or not value.isascii() or not value.isdecimal():
        raise MemberError(f"select a disk with --member id:disk:INDEX and its sectors with {sector_options}. "
                          "Use retrore members to list disk IDs")
    try:
        return int(value)
    except ValueError:
        raise MemberError("invalid disk index") from None

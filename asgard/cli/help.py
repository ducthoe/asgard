# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import textwrap
from collections.abc import Sequence
from typing import TextIO

_BOLD = "\x1b[1m"
_RESET = "\x1b[0m"
_OPTION = re.compile(r"(?<!\S)--?[A-Za-z][A-Za-z0-9-]*")


def _help_width() -> int:
    return max(40, min(shutil.get_terminal_size(fallback=(80, 24)).columns - 2, 120))


class CompactHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog: str):
        super().__init__(prog, width=_help_width(), indent_increment=2)

    def _format_usage(
        self, usage: str | None, actions: list[argparse.Action], groups: list[object], prefix: str | None
    ):
        formatted = super()._format_usage(usage, actions, groups, prefix)
        usage_line = " ".join(line.strip() for line in formatted.partition("\n\n")[0].splitlines())
        label = prefix or "usage: "
        return (
            "\n".join(
                textwrap.wrap(
                    usage_line[len(label) :],
                    width=self._width,
                    initial_indent=label,
                    subsequent_indent="  ",
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
            + "\n\n"
        )

    def _format_action(self, action: argparse.Action) -> str:
        label = self._format_action_invocation(action)
        indent = " " * self._current_indent
        parts: list[str] = []
        if action.help and (description := self._expand_help(action).strip()):
            inline_prefix = f"{indent}{label}  "
            if self._width - len(inline_prefix) >= max(24, self._width // 3):
                prefix = inline_prefix
                continuation = " " * len(prefix)
            else:
                parts.append(f"{indent}{label}\n")
                prefix = continuation = f"{indent}  "
            lines = self._split_lines(description, max(10, self._width - len(continuation)))
            parts.append(f"{prefix}{lines[0]}\n")
            parts.extend(f"{continuation}{line}\n" for line in lines[1:])
        else:
            parts.append(f"{indent}{label}\n")
        for subaction in self._iter_indented_subactions(action):
            parts.append(self._format_action(subaction))
        return self._join_parts(parts)


CommandGroups = Sequence[tuple[str, Sequence[tuple[str, str]]]]
Examples = Sequence[tuple[str, str]]


class HelpParser(argparse.ArgumentParser):
    def __init__(
        self,
        *args: object,
        command_groups: CommandGroups | None = None,
        examples: Examples = (),
        **kwargs: object,
    ):
        kwargs.setdefault("formatter_class", CompactHelpFormatter)
        super().__init__(*args, **kwargs)
        self.command_groups = command_groups
        self.examples = examples

    def format_help(self) -> str:
        if self.command_groups is None:
            content = super().format_help()
        else:
            lines = [f"usage: {self.prog} COMMAND [options]", "", self.description or "", ""]
            width = _help_width()
            for title, commands in self.command_groups:
                lines.append(f"{title}:")
                for name, description in commands:
                    prefix = f"  {name:<11}  "
                    lines.extend(
                        textwrap.wrap(
                            description,
                            width=width,
                            initial_indent=prefix,
                            subsequent_indent=" " * len(prefix),
                            break_long_words=False,
                        )
                    )
                lines.append("")
            lines.extend(["options:", "  -h, --help  Show help", "", f"Run '{self.prog} COMMAND --help' for details."])
            content = "\n".join(lines) + "\n"

        if self.examples:
            lines = [content.rstrip(), "", "Examples:"]
            for label, command in self.examples:
                lines.append(f"  {label}:")
                lines.extend(
                    textwrap.wrap(
                        command,
                        width=_help_width(),
                        initial_indent="    ",
                        subsequent_indent="      ",
                        break_long_words=False,
                        break_on_hyphens=False,
                    )
                )
            content = "\n".join(lines) + "\n"
        return content

    def print_help(self, file: TextIO | None = None) -> None:
        output = sys.stdout if file is None else file
        content = self.format_help()
        if output.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb":
            content = _bold_help(content, self.command_groups)
        output.write(content)


def _bold_help(content: str, groups: CommandGroups | None) -> str:
    commands = {name for _title, entries in groups or () for name, _description in entries}
    lines: list[str] = []
    for line in content.splitlines(keepends=True):
        if line.startswith("usage:"):
            line = f"{_BOLD}usage:{_RESET}{line[len('usage:') :]}"
        elif line and not line[0].isspace() and line.rstrip().endswith(":"):
            heading = line.rstrip("\n")
            line = f"{_BOLD}{heading}{_RESET}" + ("\n" if line.endswith("\n") else "")
        elif line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":"):
            label = line[2:].rstrip("\n")
            line = f"  {_BOLD}{label}{_RESET}" + ("\n" if line.endswith("\n") else "")
        elif match := re.match(r"^(\s+)(\S+)", line):
            indent, word = match.groups()
            if word in commands:
                line = f"{indent}{_BOLD}{word}{_RESET}{line[match.end() :]}"
            elif word.startswith("-"):
                parts = re.split(r"( {2,})", line[len(indent) :], maxsplit=1)
                label, rest = parts[0], "".join(parts[1:])
                styled = _OPTION.sub(lambda option: f"{_BOLD}{option.group()}{_RESET}", label)
                line = f"{indent}{styled}{rest}"
        lines.append(line)
    return "".join(lines)

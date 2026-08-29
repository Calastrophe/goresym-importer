from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from binaryninja import BinaryView, Component, Symbol, SymbolType, Type, log_info, log_warn
from pydantic import ValidationError

from .models import FunctionMetadata, GoReSymError as GoReSymErrorModel, GoReSymMetadata, StringEntry, parse_goresym_json


class GoReSymError(RuntimeError): pass


@dataclass
class ImportReport:
  user_functions:int = 0
  std_functions:int = 0
  strings:int = 0
  functions_created:int = 0
  components_created:int = 0
  skipped:int = 0

  @property
  def functions(self) -> int: return self.user_functions + self.std_functions
  def __str__(self) -> str:
    return (f"GoReSym: functions={self.functions} (user={self.user_functions}, std={self.std_functions}), "
            f"strings={self.strings}, created={self.functions_created}, "
            f"components={self.components_created}, skipped={self.skipped}")


def load_metadata(path:str|Path) -> GoReSymMetadata:
  try: data = Path(path).read_bytes()
  except OSError as e: raise GoReSymError(f"failed to read GoReSym JSON: {e}") from e
  try: result = parse_goresym_json(data)
  except ValidationError as e:
    error = e.errors(include_url=False)[0]
    location = ".".join(map(str, error["loc"]))
    raise GoReSymError(f"invalid GoReSym JSON at {location}: {error['msg']}") from e
  if isinstance(result, GoReSymErrorModel): raise GoReSymError(f"GoReSym reported an error: {result.error}")
  return result


def _package_name(name:str) -> str: return name or "unknown"


def _package_parts(name:str) -> tuple[str, ...]: return tuple(filter(None, _package_name(name).split("/")))


def _package_label(package:str) -> str:
  parts = [part for part in package.split("/") if part]
  if not parts: return ""
  leaf = parts[-1]
  if (version:=re.fullmatch(r"v(\d+)", leaf)) is not None and int(version[1]) >= 2 and len(parts) > 1: leaf = parts[-2]
  stem, marker, version = leaf.rpartition(".v")
  return stem if marker and version.isdigit() and int(version) >= 2 else leaf


def _function_name(function:FunctionMetadata) -> str:
  prefix = f"{function.package_name}."
  if not function.package_name or not function.full_name.startswith(prefix): return function.full_name
  return f"{_package_label(function.package_name)}.{function.full_name[len(prefix):]}"


class _Components:
  def __init__(self, bv:BinaryView, report:ImportReport, *groups:list[FunctionMetadata]|None):
    self.bv, self.report = bv, report
    self.components:dict[tuple[str, ...], Component] = {}
    self.resolved:dict[str, Component] = {}
    self.children:dict[str|None, dict[str, Component]] = {}

    package_names = {item.package_name for group in groups for item in group or []}
    packages = {_package_parts(name) for name in package_names}
    children:dict[tuple[str, ...], set[str]] = {}
    for package in packages:
      for depth, name in enumerate(package): children.setdefault(package[:depth], set()).add(name)
    self.boundaries = packages | {path for path, names in children.items() if len(names) > 1}

  def _child(self, parent:Component|None, name:str) -> Component:
    parent_id = None if parent is None else parent.guid
    if (children:=self.children.get(parent_id)) is None:
      siblings = self.bv.root_component.components if parent is None else parent.components
      children = self.children[parent_id] = {component.name:component for component in siblings}
    if name not in children:
      children[name] = self.bv.create_component(name, parent)
      self.report.components_created += 1
    return children[name]

  def get(self, package_name:str) -> Component:
    if package_name in self.resolved: return self.resolved[package_name]
    package = _package_parts(package_name)

    parent:Component|None = None
    start = 0
    for depth in range(1, len(package)+1):
      prefix = package[:depth]
      if prefix not in self.boundaries: continue
      name, start = "/".join(package[start:depth]), depth
      if prefix not in self.components: self.components[prefix] = self._child(parent, name)
      parent = self.components[prefix]
    assert parent is not None
    self.resolved[package_name] = parent
    return parent


def _apply_function(bv:BinaryView, item:FunctionMetadata, components:_Components, report:ImportReport) -> bool:
  start, name, package = item.start, _function_name(item), item.package_name
  if (segment:=bv.get_segment_at(start)) is None or not segment.executable:
    report.skipped += 1
    log_warn(f"GoReSym: skipped unmapped function {name} at 0x{start:x}")
    return False

  if (function:=bv.get_function_at(start)) is None:
    bv.create_user_function(start)
    function = bv.get_function_at(start)
    report.functions_created += 1
  if function is None:
    report.skipped += 1
    log_warn(f"GoReSym: failed to create function {name} at 0x{start:x}")
    return False

  bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, start, name, name, name))
  component = components.get(package)
  if not component.contains_function(function): component.add_function(function)
  return True


def _apply_functions(bv:BinaryView, items:list[FunctionMetadata]|None, components:_Components, report:ImportReport) -> int:
  return sum(_apply_function(bv, item, components, report) for item in items or [])


def _apply_string(bv:BinaryView, item:StringEntry, report:ImportReport) -> bool:
  start = item.start
  try: data = item.string.encode("utf-8")
  except UnicodeEncodeError:
    report.skipped += 1
    log_warn(f"GoReSym: skipped string with invalid Unicode at 0x{start:x}")
    return False
  if not data:
    report.skipped += 1
    log_warn(f"GoReSym: skipped empty string at 0x{start:x}")
    return False
  segment = bv.get_segment_at(start)
  if segment is None or start+len(data) > segment.end:
    report.skipped += 1
    log_warn(f"GoReSym: skipped unmapped string at 0x{start:x}")
    return False
  if bv.read(start, len(data)) != data:
    report.skipped += 1
    log_warn(f"GoReSym: skipped string with mismatched bytes at 0x{start:x}")
    return False

  string_type = Type.array(Type.char(), len(data))
  existing = bv.get_data_var_at(start)
  if existing is not None and not existing.auto_discovered and existing.type != string_type:
    report.skipped += 1
    log_warn(f"GoReSym: preserved conflicting user data variable at 0x{start:x}")
    return False
  if existing is None or existing.auto_discovered: bv.define_user_data_var(start, string_type)

  symbol_name = f"goresym_string_{start:x}"
  if not any(symbol.name == symbol_name for symbol in bv.get_symbols(start, 1)):
    bv.define_user_symbol(Symbol(SymbolType.DataSymbol, start, symbol_name))
  return True


def _apply_strings(bv:BinaryView, items:list[StringEntry]|None, report:ImportReport) -> int:
  return sum(_apply_string(bv, item, report) for item in items or [])


def apply_metadata(bv:BinaryView, metadata:GoReSymMetadata) -> ImportReport:
  report = ImportReport()
  components = _Components(bv, report, metadata.std_functions, metadata.user_functions)
  with bv.undoable_transaction():
    report.std_functions = _apply_functions(bv, metadata.std_functions, components, report)
    report.user_functions = _apply_functions(bv, metadata.user_functions, components, report)
    report.strings = _apply_strings(bv, metadata.strings, report)
  bv.update_analysis()
  log_info(str(report))
  return report


__all__ = ["GoReSymError", "ImportReport", "apply_metadata", "load_metadata"]

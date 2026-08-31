from __future__ import annotations

import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from binaryninja import BinaryView, Component, Endianness, Symbol, SymbolType, Type, log_info, log_warn
from pydantic import ValidationError

from .models import FunctionMetadata, GoReSymError as GoReSymErrorModel, GoReSymMetadata, GoSlice, RecoveredType, StringEntry, parse_goresym_json
from .string_inference import (
  annotate_call_string_references, apply_inferred_strings, infer_string_candidates, metadata_strings,
)


METADATA_KEY = "goresym.import.v1"
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_INVALID_SYMBOL = re.compile(r"[^A-Za-z0-9_.$]")
_REPEATED_UNDERSCORE = re.compile(r"_+")
_ARCHES = {
  "386":{"x86"}, "amd64":{"x86_64"}, "arm":{"armv7", "armv7eb"}, "arm64":{"aarch64"},
  "loong64":{"loongarch64"}, "mips":{"mips32"}, "mipsle":{"mipsel32"},
  "mips64":{"mips64"}, "mips64le":{"mipsel64"},
  "ppc64":{"ppc64"}, "ppc64le":{"ppc64_le"}, "riscv64":{"riscv64", "rv64gc"},
  "s390x":{"s390x"}, "wasm":{"wasm32"},
}


class GoReSymError(RuntimeError): pass


class _Stages:
  def __init__(self, callback:Callable[[str], None]|None):
    self.callback, self.current, self.started = callback, "", time.monotonic()

  def set(self, message:str):
    now = time.monotonic()
    if self.current: log_info(f"GoReSym: {self.current} completed in {now-self.started:.1f}s")
    self.current, self.started = message, now
    log_info(f"GoReSym: {message}")
    if self.callback is not None: self.callback(message)

  def finish(self):
    if self.current: log_info(f"GoReSym: {self.current} completed in {time.monotonic()-self.started:.1f}s")


def _sample(items:list[int], limit:int) -> list[int]:
  if len(items) <= limit: return items
  return items[::max(1, len(items)//limit)][:limit]


@dataclass(frozen=True)
class _AddressMap:
  delta:int

  @classmethod
  def from_view(cls, bv:BinaryView, metadata:GoReSymMetadata) -> _AddressMap:
    original = bv.original_image_base if hasattr(bv, "original_image_base") else bv.original_base
    functions = (metadata.user_functions or [])+(metadata.std_functions or [])
    function_starts = [item.start for item in functions]
    requested = bv.image_base-original
    candidates = {0, requested}
    if metadata.module_meta.text_va:
      candidates.update(section.start-metadata.module_meta.text_va for section in bv.sections.values()
                        if section.name in {".text", "__text"})
      candidates.update(segment.start-metadata.module_meta.text_va for segment in bv.segments if segment.executable)
    if (rt0:=next((item for item in metadata.std_functions or [] if "_rt0_" in item.full_name), None)) is not None:
      candidates.add(bv.entry_point-rt0.start)

    current_starts = {function.start for function in bv.functions}
    current = _sample(sorted(current_starts), 4096)
    sample = _sample(function_starts, 32)
    if sample and current:
      candidates.update(delta for delta, _ in Counter(address-start for start in sample for address in current).most_common(4))

    executable_starts = {segment.start for segment in bv.segments if segment.executable}
    executable_starts |= {section.start for section in bv.sections.values() if section.name in {".text", "__text"}}
    landmarks = tuple(address for address in (metadata.tab_meta.va, metadata.module_meta.va, metadata.module_meta.types) if address)

    def score(delta:int):
      exact = sum(start+delta in current_starts for start in function_starts)
      executable = sum((segment:=bv.get_segment_at(start+delta)) is not None and segment.executable for start in function_starts)
      text_start = int(metadata.module_meta.text_va+delta in executable_starts)
      mapped_landmarks = sum(bv.get_segment_at(address+delta) is not None for address in landmarks)
      return (exact, text_start, executable, mapped_landmarks, delta == 0, delta == requested,
              -abs(delta), -delta)
    return cls(max(candidates, key=score))

  def __call__(self, address:int) -> int: return address+self.delta if address else 0


@dataclass
class ImportReport:
  user_functions:int = 0
  std_functions:int = 0
  strings:int = 0
  strings_inferred:int = 0
  string_references:int = 0
  functions_created:int = 0
  components_created:int = 0
  type_descriptors:int = 0
  type_symbols:int = 0
  interface_symbols:int = 0
  runtime_symbols:int = 0
  runtime_arrays:int = 0
  preserved_conflicts:int = 0
  skipped:int = 0
  address_delta:int = 0

  @property
  def functions(self) -> int: return self.user_functions+self.std_functions

  @property
  def conflicts(self) -> int: return self.preserved_conflicts

  def __str__(self) -> str:
    return (f"GoReSym: functions={self.functions} (user={self.user_functions}, std={self.std_functions}), strings={self.strings}, "
            f"inferred_strings={self.strings_inferred}, string_refs={self.string_references}, "
            f"type_descriptors={self.type_descriptors}, type_symbols={self.type_symbols}, "
            f"interfaces={self.interface_symbols}, runtime={self.runtime_symbols}/{self.runtime_arrays}, "
            f"created={self.functions_created}, components={self.components_created}, conflicts={self.preserved_conflicts}, "
            f"skipped={self.skipped}, delta={self.address_delta:+#x}")


def load_metadata(path:str|Path) -> GoReSymMetadata:
  try:
    data = Path(path).read_bytes()
  except OSError as error:
    raise GoReSymError(f"failed to read GoReSym JSON: {error}") from error
  try:
    result = parse_goresym_json(data)
  except ValidationError as error:
    detail = error.errors(include_url=False)[0]
    location = ".".join(map(str, detail["loc"]))
    raise GoReSymError(f"invalid GoReSym JSON at {location}: {detail['msg']}") from error
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


def _segment_at(bv:BinaryView, address:int, allow_end:bool = False):
  segment = bv.get_segment_at(address)
  return segment if segment is not None or not allow_end or not address else bv.get_segment_at(address-1)


def _validate_view(bv:BinaryView, metadata:GoReSymMetadata, mapper:_AddressMap) -> list[str]:
  if bv.arch is None: raise GoReSymError("Binary View has no architecture")
  if metadata.tab_meta.pointer_size != bv.arch.address_size:
    raise GoReSymError(f"pointer-size mismatch: JSON={metadata.tab_meta.pointer_size}, view={bv.arch.address_size}")

  expected_endian = Endianness.LittleEndian if metadata.tab_meta.endianess == "LittleEndian" else Endianness.BigEndian
  if bv.endianness != expected_endian:
    raise GoReSymError(f"endianness mismatch: JSON={metadata.tab_meta.endianess}, view={bv.endianness.name}")

  warnings = []
  go_arch, view_arch = metadata.arch.lower(), bv.arch.name.lower()
  if go_arch in _ARCHES and view_arch not in _ARCHES[go_arch]:
    raise GoReSymError(f"architecture mismatch: JSON={metadata.arch}, view={bv.arch.name}")
  if go_arch not in _ARCHES:
    warnings.append(f"unrecognized Go architecture {metadata.arch}; pointer size and endianness still match")

  if metadata.os and bv.platform is not None:
    platform = bv.platform.name.lower()
    aliases = {"darwin":{"darwin", "mac"}, "windows":{"windows"}, "linux":{"linux"}}.get(metadata.os.lower())
    if aliases is not None and not any(alias in platform for alias in aliases):
      warnings.append(f"OS differs: JSON={metadata.os}, view={bv.platform.name}")

  functions = (metadata.user_functions or [])+(metadata.std_functions or [])
  mapped_function = any((segment:=bv.get_segment_at(mapper(item.start))) is not None and segment.executable for item in functions)
  landmarks = (metadata.tab_meta.va, metadata.module_meta.va, metadata.module_meta.types, metadata.module_meta.typelinks.data)
  mapped_landmark = any(address and _segment_at(bv, mapper(address)) is not None for address in landmarks)
  if not mapped_function and not mapped_landmark:
    raise GoReSymError(f"metadata addresses do not map into this Binary View (delta {mapper.delta:+#x})")
  return warnings


class _Components:
  def __init__(self, bv:BinaryView, report:ImportReport, metadata:GoReSymMetadata):
    self.bv, self.report = bv, report
    self.by_path:dict[tuple[str, tuple[str, ...]], Component] = {}
    self.by_package:dict[tuple[str, str], Component] = {}
    self.children_by_parent:dict[str|None, dict[str, Component]] = {}
    self.roots:dict[str, Component] = {}
    build = metadata.build_info
    self.main_paths = tuple(filter(None, dict.fromkeys((build.path, build.main.path))))

    packages = {(self._group(item.package_name, standard), _package_parts(item.package_name))
                for standard, items in ((False, metadata.user_functions), (True, metadata.std_functions)) for item in items or []}
    children:dict[tuple[str, tuple[str, ...]], set[str]] = {}
    for group, package in packages:
      for depth, name in enumerate(package): children.setdefault((group, package[:depth]), set()).add(name)
    self.component_paths = packages|{path for path, names in children.items() if len(names) > 1}

  def _group(self, package:str, standard:bool) -> str:
    if standard: return "stdlib"
    if package == "main" or any(package == path or package.startswith(path+"/") for path in self.main_paths): return "main"
    return "dependencies"

  def _child(self, parent:Component|None, name:str) -> Component:
    parent_id = None if parent is None else parent.guid
    if (children:=self.children_by_parent.get(parent_id)) is None:
      siblings = self.bv.root_component.components if parent is None else parent.components
      children = self.children_by_parent[parent_id] = {component.name:component for component in siblings}
    if name not in children:
      children[name] = self.bv.create_component(name, parent)
      self.report.components_created += 1
    return children[name]

  def get(self, package_name:str, standard:bool = False) -> Component:
    group = self._group(package_name, standard)
    key = group, package_name
    if key in self.by_package: return self.by_package[key]
    package = _package_parts(package_name)

    if group not in self.roots: self.roots[group] = self._child(None, group)
    parent = self.roots[group]
    start = 0
    for depth in range(1, len(package)+1):
      prefix = package[:depth]
      path = group, prefix
      if path not in self.component_paths: continue
      name, start = "/".join(package[start:depth]), depth
      if path not in self.by_path: self.by_path[path] = self._child(parent, name)
      parent = self.by_path[path]
    self.by_package[key] = parent
    return parent


def _apply_function(bv:BinaryView, item:FunctionMetadata, mapper:_AddressMap, components:_Components, report:ImportReport,
                    standard:bool) -> bool:
  start, name, package = mapper(item.start), _function_name(item), item.package_name
  if (segment:=bv.get_segment_at(start)) is None or not segment.executable:
    report.skipped += 1
    log_warn(f"GoReSym: skipped unmapped function {name} at 0x{start:x}")
    return False

  if (function:=bv.get_function_at(start)) is None:
    function = bv.create_user_function(start)
    report.functions_created += 1
  if function is None:
    report.skipped += 1
    log_warn(f"GoReSym: failed to create function {name} at 0x{start:x}")
    return False

  bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, start, name, name, name))
  component = components.get(package, standard)
  if not component.contains_function(function): component.add_function(function)
  return True


def _apply_functions(bv:BinaryView, items:list[FunctionMetadata]|None, mapper:_AddressMap, components:_Components,
                     report:ImportReport, standard:bool) -> int:
  return sum(_apply_function(bv, item, mapper, components, report, standard) for item in items or [])


def _apply_string(bv:BinaryView, item:StringEntry, mapper:_AddressMap, report:ImportReport) -> bool:
  start = mapper(item.start)
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
    report.preserved_conflicts += 1
    log_warn(f"GoReSym: preserved conflicting user data variable at 0x{start:x}")
    return False
  if existing is None or existing.auto_discovered: bv.define_user_data_var(start, string_type)

  symbol_name = f"goresym_string_{start:x}"
  if not any(symbol.name == symbol_name for symbol in bv.get_symbols(start, 1)):
    bv.define_user_symbol(Symbol(SymbolType.DataSymbol, start, symbol_name))
  return True


def _apply_strings(bv:BinaryView, items:list[StringEntry]|None, mapper:_AddressMap, report:ImportReport) -> int:
  return sum(_apply_string(bv, item, mapper, report) for item in items or [])


def _define_data_symbol(bv:BinaryView, address:int, name:str, allow_end:bool = False) -> bool:
  if not address or _segment_at(bv, address, allow_end) is None: return False
  if not any(symbol.address == address and symbol.name == name for symbol in bv.get_symbols(address, 1)):
    bv.define_user_symbol(Symbol(SymbolType.DataSymbol, address, name))
  return True


def _user_data_conflict(user_data:tuple, address:int, typ:Type):
  end = address+typ.width
  for item in user_data:
    item_end = item.address+max(1, item.type.width)
    if item.address < end and address < item_end and (item.address != address or item.type != typ): return item
  return None


def _apply_runtime_array(bv:BinaryView, item:GoSlice, mapper:_AddressMap, name:str, element:Type,
                         user_data:tuple, components:_Components, report:ImportReport) -> bool:
  if not item.data or not item.length: return False
  address = mapper(item.data)
  if (segment:=bv.get_segment_at(address)) is None or element.width <= 0 or item.length > (segment.end-address)//element.width:
    report.skipped += 1
    log_warn(f"GoReSym: skipped invalid {name} array at 0x{address:x}")
    return False
  array = Type.array(element, item.length)
  existing = bv.get_data_var_at(address)
  if _user_data_conflict(user_data, address, array) is not None:
    report.preserved_conflicts += 1
    report.skipped += 1
    log_warn(f"GoReSym: preserved conflicting user data variable for {name} at 0x{address:x}")
    return False
  if existing is None or existing.auto_discovered: bv.define_user_data_var(address, array)
  _define_data_symbol(bv, address, name)
  if (data_var:=bv.get_data_var_at(address)) is not None:
    component = components.get("runtime", True)
    if not component.contains_data_variable(data_var): component.add_data_variable(data_var)
  return True


def _apply_runtime(bv:BinaryView, metadata:GoReSymMetadata, mapper:_AddressMap, components:_Components, report:ImportReport):
  module = metadata.module_meta
  slices = (module.typelinks, module.itablinks, module.legacy_types)
  user_data = tuple(item for item in bv.data_vars.values() if not item.auto_discovered) if any(item.length for item in slices) else ()
  symbols = (
    (metadata.tab_meta.va, "runtime.pclntab", False), (module.va, "runtime.firstmoduledata", False),
    (module.types, "runtime.types", False), (module.etypes, "runtime.etypes", True),
    (module.typelinks.data, "runtime.typelinks", False), (module.itablinks.data, "runtime.itablinks", False),
    (module.legacy_types.data, "runtime.legacytypelinks", False),
  )
  report.runtime_symbols = sum(_define_data_symbol(bv, mapper(address), name, allow_end) for address, name, allow_end in symbols)
  pointer = Type.pointer(bv.arch, Type.void())
  report.runtime_arrays = sum((
    _apply_runtime_array(bv, module.typelinks, mapper, "runtime.typelinks", Type.int(4, True), user_data, components, report),
    _apply_runtime_array(bv, module.itablinks, mapper, "runtime.itablinks", pointer, user_data, components, report),
    _apply_runtime_array(bv, module.legacy_types, mapper, "runtime.legacytypelinks", pointer, user_data, components, report),
  ))


def _record_score(item:RecoveredType) -> bool: return bool(item.c_string)


def _type_descriptors(metadata:GoReSymMetadata) -> dict[int, RecoveredType]:
  descriptors = {}
  for items in (metadata.types, metadata.interfaces):
    for item in items or []:
      current = descriptors.get(item.va)
      if current is None or _record_score(item) > _record_score(current): descriptors[item.va] = item
  return descriptors


def _symbol_token(name:str) -> str:
  token = _INVALID_SYMBOL.sub("_", name)
  token = _REPEATED_UNDERSCORE.sub("_", token).strip("_") or "unknown"
  return "_"+token if token[0].isdigit() else token


def _type_symbol(item:RecoveredType) -> tuple[str, bool]:
  is_itab = not item.c_string and item.string.startswith("interface_")
  identity = item.c_string if _IDENTIFIER.fullmatch(item.c_string) else _symbol_token(item.string)
  return f"go.{'itab' if is_itab else 'type'}.{identity}", is_itab


def _apply_type_symbols(bv:BinaryView, descriptors:dict[int, RecoveredType], mapper:_AddressMap,
                        report:ImportReport):
  used_names = {}
  for raw_address, item in descriptors.items():
    address = mapper(raw_address)
    if not address or bv.get_segment_at(address) is None:
      report.skipped += 1
      continue
    name, is_itab = _type_symbol(item)
    if name in used_names and used_names[name] != address: name += f"_{raw_address:x}"
    used_names[name] = address
    if _define_data_symbol(bv, address, name):
      if is_itab: report.interface_symbols += 1
      else: report.type_symbols += 1
    report.type_descriptors += 1


def _metadata_state(metadata:GoReSymMetadata, mapper:_AddressMap, report:ImportReport, diagnostics:list[str]) -> dict:
  return {
    "schema_version":1,
    "version":metadata.version,
    "build_id":metadata.build_id,
    "arch":metadata.arch,
    "os":metadata.os,
    "address_delta":mapper.delta,
    "tab_meta":metadata.tab_meta.model_dump(by_alias=True, exclude_none=True),
    "module_meta":metadata.module_meta.model_dump(by_alias=True, exclude_none=True),
    "build_info":metadata.build_info.model_dump(by_alias=True, exclude_none=True),
    "files":sorted(set(metadata.files or [])),
    "counts":asdict(report),
    "diagnostics":diagnostics,
  }


def _format_module(module:dict, prefix:str = "") -> list[str]:
  text = f"{module.get('Path', '')} {module.get('Version', '')}".rstrip()
  lines = [prefix+text]
  if checksum:=module.get("Sum"): lines.append(prefix+f"  Sum: {checksum}")
  if replacement:=module.get("Replace"):
    lines.append(prefix+"  Replaced by:")
    lines.extend(_format_module(replacement, prefix+"    "))
  return lines


def _report_address(value:int, delta:int) -> str:
  if not value: return "<none>"
  mapped = value+delta
  return f"0x{value:x}" if not delta else f"0x{value:x} -> 0x{mapped:x}"


def format_imported_metadata(state:dict) -> str:
  build, tab, module = state.get("build_info", {}), state.get("tab_meta", {}), state.get("module_meta", {})
  delta = state.get("address_delta", 0)
  lines = [
    "GoReSym Import Metadata", "",
    f"Go version: {state.get('version', '')}",
    f"Build Go version: {build.get('GoVersion', '')}",
    f"Target: {state.get('os', '')}/{state.get('arch', '')}",
    f"Build ID: {state.get('build_id', '')}",
    f"Address delta: {delta:+#x}",
    f"Main package: {build.get('Path', '')}", "", "Main module:",
  ]
  lines.extend(_format_module(build.get("Main", {}), "  "))

  dependencies = build.get("Deps") or []
  lines.extend(("", f"Dependencies ({len(dependencies)}):"))
  for dependency in dependencies: lines.extend(_format_module(dependency, "  "))
  settings = build.get("Settings") or []
  lines.extend(("", f"Build settings ({len(settings)}):"))
  lines.extend(f"  {setting.get('Key', '')}={setting.get('Value', '')}" for setting in settings)

  runtime_addresses = (
    ("pclntab", tab.get("VA", 0)), ("firstmoduledata", module.get("VA", 0)),
    ("text", module.get("TextVA", 0)), ("types", module.get("Types", 0)), ("etypes", module.get("ETypes", 0)),
    ("typelinks", (module.get("Typelinks") or {}).get("Data", 0)),
    ("itablinks", (module.get("ITablinks") or {}).get("Data", 0)),
    ("legacy typelinks", (module.get("LegacyTypes") or {}).get("Data", 0)),
  )
  lines.extend(("", "Runtime landmarks:"))
  lines.extend(f"  {name}: {_report_address(address, delta)}" for name, address in runtime_addresses)

  counts = state.get("counts", {})
  lines.extend(("", "Import counts:"))
  lines.extend(f"  {key}: {value}" for key, value in counts.items())
  files, diagnostics = state.get("files", []), state.get("diagnostics", [])
  lines.extend(("", f"Source files ({len(files)}):"))
  lines.extend(f"  {path}" for path in files)
  lines.extend(("", f"Diagnostics ({len(diagnostics)}):"))
  lines.extend(f"  {diagnostic}" for diagnostic in diagnostics)
  return "\n".join(lines)


def apply_metadata(
  bv:BinaryView, metadata:GoReSymMetadata, progress:Callable[[str], None]|None = None,
) -> ImportReport:
  stages = _Stages(progress)
  stages.set("validating target and mapping addresses")
  report, mapper = ImportReport(), _AddressMap.from_view(bv, metadata)
  report.address_delta = mapper.delta
  diagnostics = _validate_view(bv, metadata, mapper)
  for warning in diagnostics: log_warn(f"GoReSym: {warning}")

  descriptors = _type_descriptors(metadata)
  components = _Components(bv, report, metadata)
  with bv.undoable_transaction():
    stages.set(f"applying {len(metadata.std_functions or []):,} standard-library functions")
    report.std_functions = _apply_functions(bv, metadata.std_functions, mapper, components, report, True)
    stages.set(f"applying {len(metadata.user_functions or []):,} user functions")
    report.user_functions = _apply_functions(bv, metadata.user_functions, mapper, components, report, False)
    stages.set(f"applying {len(metadata.strings or []):,} GoReSym strings")
    report.strings = _apply_strings(bv, metadata.strings, mapper, report)
    stages.set("applying runtime landmarks")
    _apply_runtime(bv, metadata, mapper, components, report)
    stages.set(f"applying {len(descriptors):,} type-descriptor symbols")
    _apply_type_symbols(bv, descriptors, mapper, report)
  stages.set("waiting for Binary Ninja analysis (pass 1 of 2)")
  bv.update_analysis_and_wait()
  stages.set("inferring Go strings from calls and stored headers")
  inferred = infer_string_candidates(bv, metadata, mapper)
  known = metadata_strings(metadata, mapper)
  inferred = {address:data for address, data in inferred.items() if address not in known}
  with bv.undoable_transaction():
    stages.set(f"applying {len(inferred):,} inferred exact strings")
    applied = apply_inferred_strings(bv, inferred)
    report.strings_inferred = applied.count
    report.preserved_conflicts += applied.conflicts
  stages.set("waiting for Binary Ninja analysis (pass 2 of 2)")
  bv.update_analysis_and_wait()
  stages.set("annotating propagated string pointers in HLIL")
  report.string_references = annotate_call_string_references(bv, inferred|known)
  stages.set("storing import metadata")
  with bv.undoable_transaction():
    bv.store_metadata(METADATA_KEY, _metadata_state(metadata, mapper, report, diagnostics))
  stages.finish()
  log_info(str(report))
  return report


__all__ = ["GoReSymError", "ImportReport", "METADATA_KEY", "apply_metadata", "format_imported_metadata", "load_metadata"]

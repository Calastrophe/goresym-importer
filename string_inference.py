import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import cache

from binaryninja import (
  BinaryView, DerivedString, DerivedStringLocation, DerivedStringLocationType, HighLevelILOperation,
  MediumLevelILOperation, RegisterValueType, Symbol, SymbolType, Type,
)

from .models import GoReSymMetadata


_MAX_STRING_LENGTH = 0x4000
_STACK_SCAN_BYTES = 0x100
_CONSTANTS = {RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue}
_CALLS = {
  HighLevelILOperation.HLIL_CALL,
  HighLevelILOperation.HLIL_CALL_SSA,
  HighLevelILOperation.HLIL_TAILCALL,
}

# Binary Ninja register names in Go ABIInternal order. Architectures not listed
# here use ABI0, where the same pointer/length words are recovered from the stack.
_REGISTER_ABIS = {
  "amd64":((1, 17), ("rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11")),
  "arm64":((1, 18), tuple(f"x{index}" for index in range(16))),
  "loong64":((1, 19), tuple(f"r{index}" for index in range(4, 20))),
  "ppc64":((1, 18), tuple(f"r{index}" for index in range(3, 11))+tuple(f"r{index}" for index in range(14, 18))),
  "ppc64le":((1, 18), tuple(f"r{index}" for index in range(3, 11))+tuple(f"r{index}" for index in range(14, 18))),
  "riscv64":((1, 19), tuple(f"a{index}" for index in range(8))+("s0", "s1")+tuple(f"s{index}" for index in range(2, 8))),
  "s390x":((1, 26), tuple(f"r{index}" for index in range(2, 10))),
}


@dataclass(frozen=True)
class AppliedStrings:
  count:int
  conflicts:int


def _version(value:str) -> tuple[int, int]:
  match = re.search(r"(?:go)?(\d+)\.(\d+)", value)
  return (int(match[1]), int(match[2])) if match is not None else (0, 0)


def go_argument_registers(metadata:GoReSymMetadata, available:Iterable[str]|None = None) -> tuple[str, ...]:
  abi = _REGISTER_ABIS.get(metadata.arch.lower())
  version = max(_version(metadata.version), _version(metadata.build_info.go_version))
  if abi is None or version < abi[0]: return ()
  if metadata.arch.lower() == "amd64" and version == (1, 17) and metadata.os.lower() not in {"linux", "darwin", "windows"}:
    return ()
  registers = abi[1]
  if available is None: return registers
  names = set(available)
  return registers if all(register in names for register in registers) else ()


def _string_bytes(bv:BinaryView, address:int, length:int) -> bytes|None:
  if not 0 < length <= _MAX_STRING_LENGTH: return None
  segment = bv.get_segment_at(address)
  if segment is None or segment.executable or segment.writable or address+length > segment.end: return None
  data = bv.read(address, length)
  try: text = data.decode("utf-8")
  except UnicodeDecodeError: return None
  if not text or not all(char.isprintable() or char in "\t\r\n" for char in text): return None
  return data


def _constant(value, pointer:bool = False) -> int|None:
  allowed = _CONSTANTS if pointer else {RegisterValueType.ConstantValue}
  return value.value if value.type in allowed else None


def _record_pairs(values:list, lengths:dict[int, set[int]], read:Callable[[int, int], bytes|None]):
  for index, (pointer, size) in enumerate(zip(values, values[1:])):
    address, length = _constant(pointer, True), _constant(size)
    if address is None or length is None: continue
    # A third integer at least as large as len is much more likely to be a
    # []byte/string-like slice (data, len, cap) than a Go string.
    if index+2 < len(values) and (capacity:=_constant(values[index+2])) is not None and capacity >= length: continue
    if read(address, length) is None: continue
    lengths.setdefault(address, set()).add(length)


def _stack_values(function, address:int, pointer_size:int) -> list:
  arch = getattr(function, "arch", None)
  stack_pointer = getattr(arch, "stack_pointer", None)
  if stack_pointer is None or not hasattr(function, "get_stack_contents_at"): return []
  stack = function.get_reg_value_at(address, stack_pointer)
  if stack.type != RegisterValueType.StackFrameOffset: return []
  return [function.get_stack_contents_at(address, stack.value+offset, pointer_size)
          for offset in range(0, _STACK_SCAN_BYTES, pointer_size)]


def _mlil_constant(expression) -> int|None:
  if expression.operation in {MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR}:
    return expression.constant
  value = expression.value
  return value.value if value.type in _CONSTANTS else None


def _store_location(expression) -> tuple[tuple[str, int], int]|None:
  offset = 0
  if expression.operation == MediumLevelILOperation.MLIL_ADD:
    left, right = expression.left, expression.right
    if (constant:=_mlil_constant(right)) is not None: expression, offset = left, constant
    elif (constant:=_mlil_constant(left)) is not None: expression, offset = right, constant
    else: return None
  if expression.operation == MediumLevelILOperation.MLIL_VAR:
    return ("var", expression.src.identifier), offset
  if expression.operation == MediumLevelILOperation.MLIL_CONST_PTR:
    return ("address", expression.constant), offset
  return None


def _stored_string_pairs(function, pointer_size:int, lengths:dict[int, set[int]], read:Callable[[int, int], bytes|None]):
  mlil = getattr(function, "mlil", None)
  if mlil is None: return
  for block in mlil:
    fields:dict[tuple[str, int], dict[int, tuple[int, int]]] = {}
    for instruction in block:
      if instruction.operation != MediumLevelILOperation.MLIL_STORE: continue
      location, value = _store_location(instruction.dest), _mlil_constant(instruction.src)
      if location is None or value is None: continue
      base, offset = location
      if offset not in {0, pointer_size, pointer_size*2}: continue
      fields.setdefault(base, {})[offset] = value, instruction.address
    for values in fields.values():
      if 0 not in values or pointer_size not in values: continue
      address, pointer_site = values[0]
      length, length_site = values[pointer_size]
      if abs(pointer_site-length_site) > 0x40: continue
      if pointer_size*2 in values and values[pointer_size*2][0] >= length: continue
      if read(address, length) is None: continue
      lengths.setdefault(address, set()).add(length)


def infer_string_candidates(
  bv:BinaryView, metadata:GoReSymMetadata, mapper:Callable[[int], int],
) -> dict[int, bytes]:
  available = getattr(getattr(bv, "arch", None), "regs", None)
  registers = go_argument_registers(metadata, available)
  pointer_size = metadata.tab_meta.pointer_size
  lengths:dict[int, set[int]] = {}

  @cache
  def read(address:int, length:int) -> bytes|None: return _string_bytes(bv, address, length)

  starts = {mapper(item.start) for item in (metadata.user_functions or [])+(metadata.std_functions or [])}
  for start in starts:
    if (function:=bv.get_function_at(start)) is None: continue
    _stored_string_pairs(function, pointer_size, lengths, read)
    for site in function.call_sites:
      if registers:
        _record_pairs([function.get_reg_value_at(site.address, register) for register in registers], lengths, read)
      else:
        _record_pairs(_stack_values(function, site.address, pointer_size), lengths, read)
  return {address:data for address, candidates in lengths.items() if len(candidates) == 1
          if (data:=read(address, next(iter(candidates)))) is not None}


def metadata_strings(metadata:GoReSymMetadata, mapper:Callable[[int], int]) -> dict[int, bytes]:
  strings = {}
  for item in metadata.strings or []:
    try: strings[mapper(item.start)] = item.string.encode("utf-8")
    except UnicodeEncodeError: pass
  return strings


def apply_inferred_strings(bv:BinaryView, strings:dict[int, bytes]) -> AppliedStrings:
  count = conflicts = 0
  for address, data in strings.items():
    expected = Type.array(Type.char(), len(data))
    existing = bv.get_data_var_at(address)
    if existing is not None and not existing.auto_discovered:
      if existing.address == address and existing.type == expected:
        count += 1
        continue
      conflicts += 1
      continue
    bv.define_user_data_var(address, expected)
    name = f"goresym_string_{address:x}"
    if not any(symbol.name == name for symbol in bv.get_symbols(address, 1)):
      bv.define_user_symbol(Symbol(SymbolType.DataSymbol, address, name))
    count += 1
  return AppliedStrings(count, conflicts)


def _expression_address(expression) -> int|None:
  values = expression.possible_values
  if values.type in _CONSTANTS: return values.value
  value = expression.value
  return value.value if value.type in _CONSTANTS else None


def _call(expression): return expression if expression.operation in _CALLS else None


def _referencing_functions(bv:BinaryView, addresses:Iterable[int]) -> set[int]:
  return {reference.function.start for address in addresses for reference in bv.get_code_refs(address)
          if reference.function is not None}


def annotate_call_string_references(
  bv:BinaryView, strings:dict[int, bytes], starts:Iterable[int]|None = None,
) -> int:
  references = 0
  for start in set(starts) if starts is not None else _referencing_functions(bv, strings):
    if (function:=bv.get_function_at(start)) is None or (hlil:=function.hlil) is None: continue
    for root in hlil.instructions:
      for call in root.traverse(_call):
        for parameter in call.params:
          address = _expression_address(parameter)
          if address not in strings: continue
          data = strings[address]
          location = DerivedStringLocation(DerivedStringLocationType.DataBackedStringLocation, address, len(data))
          existing = parameter.derived_string_reference
          if existing is not None and existing.location == location and bytes(existing.value) == data: continue
          hlil.set_derived_string_reference_for_expr(parameter, DerivedString(data, location, None))
          references += 1
  return references


__all__ = [
  "AppliedStrings", "annotate_call_string_references", "apply_inferred_strings", "go_argument_registers",
  "infer_string_candidates", "metadata_strings",
]

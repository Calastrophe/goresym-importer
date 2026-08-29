from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator


UInt32 = Annotated[int, Field(ge=0, le=(1 << 32)-1)]
UInt64 = Annotated[int, Field(ge=0, le=(1 << 64)-1)]


class GoReSymModel(BaseModel): model_config = ConfigDict(populate_by_name=True, extra="ignore")


class PcLnTabMetadata(GoReSymModel):
  va:UInt64 = Field(alias="VA")
  version:str = Field(alias="Version")
  endianess:str = Field(alias="Endianess")
  cpu_quantum:UInt32 = Field(alias="CpuQuantum")
  cpu_quantum_str:str = Field(alias="CpuQuantumStr")
  pointer_size:UInt32 = Field(alias="PointerSize")


class GoSlice(GoReSymModel):
  data:UInt64 = Field(0, alias="Data")
  length:UInt64 = Field(0, alias="Len")
  capacity:UInt64 = Field(0, alias="Capacity")


class ModuleData(GoReSymModel):
  va:UInt64 = Field(alias="VA")
  text_va:UInt64 = Field(0, alias="TextVA")
  types:UInt64 = Field(0, alias="Types")
  etypes:UInt64 = Field(0, alias="ETypes")
  typelinks:GoSlice = Field(default_factory=GoSlice, alias="Typelinks")
  itablinks:GoSlice = Field(default_factory=GoSlice, alias="ITablinks")
  legacy_types:GoSlice = Field(default_factory=GoSlice, alias="LegacyTypes")

  @field_validator("typelinks", "itablinks", "legacy_types", mode="before")
  @classmethod
  def null_slice(cls, value): return {} if value is None else value


class RecoveredType(GoReSymModel):
  va:UInt64 = Field(alias="VA")
  string:str = Field(alias="Str")
  c_string:str = Field(alias="CStr")
  kind:str = Field(alias="Kind")
  reconstructed:str|None = Field(None, alias="Reconstructed")
  c_reconstructed:str|None = Field(None, alias="CReconstructed")


class BuildModule(GoReSymModel):
  path:str = Field(alias="Path")
  version:str = Field(alias="Version")
  sum:str = Field(alias="Sum")
  replace:BuildModule|None = Field(None, alias="Replace")


class BuildSetting(GoReSymModel):
  key:str = Field(alias="Key")
  value:str = Field(alias="Value")


class BuildInfo(GoReSymModel):
  go_version:str = Field(alias="GoVersion")
  path:str = Field(alias="Path")
  main:BuildModule = Field(alias="Main")
  deps:list[BuildModule]|None = Field(None, alias="Deps")
  settings:list[BuildSetting]|None = Field(None, alias="Settings")


class FunctionMetadata(GoReSymModel):
  start:UInt64 = Field(alias="Start")
  end:UInt64 = Field(alias="End")
  package_name:str = Field(alias="PackageName")
  full_name:str = Field(alias="FullName")

  @model_validator(mode="after")
  def valid_range(self):
    if self.end <= self.start: raise ValueError("End must be greater than Start")
    return self


class StringEntry(GoReSymModel):
  string:str = Field(alias="Str")
  start:UInt64 = Field(alias="Start")


class GoReSymMetadata(GoReSymModel):
  version:str = Field(alias="Version")
  build_id:str = Field(alias="BuildId")
  arch:str = Field(alias="Arch")
  os:str = Field(alias="OS")
  tab_meta:PcLnTabMetadata = Field(alias="TabMeta")
  module_meta:ModuleData = Field(alias="ModuleMeta")
  types:list[RecoveredType]|None = Field(alias="Types")
  interfaces:list[RecoveredType]|None = Field(alias="Interfaces")
  build_info:BuildInfo = Field(alias="BuildInfo")
  files:list[str]|None = Field(alias="Files")
  user_functions:list[FunctionMetadata]|None = Field(alias="UserFunctions")
  std_functions:list[FunctionMetadata]|None = Field(alias="StdFunctions")
  strings:list[StringEntry]|None = Field(alias="Strings")


class GoReSymError(GoReSymModel): error:str


GoReSymOutput = GoReSymMetadata|GoReSymError
_output = TypeAdapter[GoReSymOutput](GoReSymOutput)
def parse_goresym_json(data:str|bytes|bytearray) -> GoReSymOutput: return _output.validate_json(data)


__all__ = ["BuildInfo", "BuildModule", "BuildSetting", "FunctionMetadata", "GoReSymError", "GoReSymMetadata", "GoSlice", "ModuleData",
           "PcLnTabMetadata", "RecoveredType", "StringEntry", "parse_goresym_json"]

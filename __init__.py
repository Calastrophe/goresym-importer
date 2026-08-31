from __future__ import annotations

from pathlib import Path

from binaryninja import (BackgroundTaskThread, BinaryView, MessageBoxButtonSet, MessageBoxIcon, PluginCommand, execute_on_main_thread,
                         get_open_filename_input, log_error, show_message_box)


_METADATA_KEY = "goresym.import.v1"


def _error(message:str, title:str = "GoReSym Import Failed"):
  log_error(f"GoReSym: {message}")
  show_message_box(title, message, MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


class _ImportTask(BackgroundTaskThread):
  def __init__(self, bv:BinaryView, path:str):
    super().__init__("GoReSym: loading and validating JSON", False)
    self.bv, self.path = bv, Path(path)

  def run(self):
    try:
      from .importer import apply_metadata, load_metadata
      metadata = load_metadata(self.path)
      apply_metadata(self.bv, metadata, lambda stage:setattr(self, "progress", f"GoReSym: {stage}"))
      self.progress = "GoReSym: import complete"
    except Exception as error:
      execute_on_main_thread(lambda message=str(error): _error(message))


def import_goresym(bv:BinaryView):
  path = get_open_filename_input("Select GoReSym JSON output", "GoReSym JSON (*.json);;All Files (*)")
  if path is None: return
  task = _ImportTask(bv, path)
  task.start()
  return task


def _stored_metadata(bv:BinaryView):
  try:
    return bv.query_metadata(_METADATA_KEY)
  except KeyError:
    return None


def show_imported_metadata(bv:BinaryView):
  from .importer import format_imported_metadata
  if not isinstance(state:=_stored_metadata(bv), dict):
    _error("No imported GoReSym metadata is stored in this Binary View", "GoReSym Metadata Unavailable")
    return
  bv.show_plain_text_report("GoReSym Import Metadata", format_imported_metadata(state))


def _valid(bv:BinaryView) -> bool: return bv.arch is not None and any(segment.executable for segment in bv.segments)


def _has_metadata(bv:BinaryView) -> bool: return isinstance(_stored_metadata(bv), dict)


PluginCommand.register(r"GoReSym\Import JSON", r"GoReSym\Import JSON", import_goresym, _valid)
PluginCommand.register(r"GoReSym\Show Imported Metadata", r"GoReSym\Show Imported Metadata", show_imported_metadata, _has_metadata)

__all__ = ["import_goresym", "show_imported_metadata"]

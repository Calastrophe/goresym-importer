from __future__ import annotations

from pathlib import Path

from binaryninja import (BackgroundTaskThread, BinaryView, MessageBoxButtonSet, MessageBoxIcon, PluginCommand, execute_on_main_thread,
                         get_open_filename_input, log_error, show_message_box)


def _error(message:str):
  log_error(f"GoReSym: {message}")
  show_message_box("GoReSym Import Failed", message, MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


class _ImportTask(BackgroundTaskThread):
  def __init__(self, bv:BinaryView, path:str):
    super().__init__("GoReSym: loading and validating JSON", False)
    self.bv, self.path = bv, Path(path)

  def run(self):
    try:
      from .importer import apply_metadata, load_metadata
      metadata = load_metadata(self.path)
      self.progress = "GoReSym: applying functions and strings"
      apply_metadata(self.bv, metadata)
      self.progress = "GoReSym: import complete"
    except Exception as e: execute_on_main_thread(lambda message=str(e): _error(message))


def import_goresym(bv:BinaryView):
  if (path:=get_open_filename_input("Select GoReSym JSON output", "GoReSym JSON (*.json);;All Files (*)")) is None: return
  task = _ImportTask(bv, path)
  task.start()
  return task


def _valid(bv:BinaryView) -> bool: return bv.arch is not None and any(segment.executable for segment in bv.segments)


PluginCommand.register(r"GoReSym\Import JSON", r"GoReSym\Import JSON", import_goresym, _valid)

__all__ = ["import_goresym"]

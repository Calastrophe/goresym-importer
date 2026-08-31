# GoReSym Importer

A Binary Ninja plugin that validates [GoReSym](https://github.com/mandiant/GoReSym) JSON output and applies recovered functions, strings, interface/type-descriptor symbols, and Go runtime landmarks.

## How to Use

1. Copy this directory into Binary Ninja's user plugin directory. If installing the plugin manually, install its Python dependency with the Python environment configured in Binary Ninja:

   ```console
   python -m pip install -r /path/to/goresym-importer/requirements.txt
   ```

2. Download or build [GoReSym](https://github.com/mandiant/GoReSym).

3. Generate JSON for the [Go](https://go.dev/) binary. Types, standard-library functions, paths, and strings require the corresponding GoReSym flags:

   ```console
   GoReSym -t -d -p -strings /path/to/binary > /path/to/goresym.json
   ```

4. Open the same binary in Binary Ninja. Rebased views are supported: the importer scores the image-base delta, executable sections, entry point, and existing functions to translate every GoReSym virtual address consistently. An import is rejected if the metadata cannot be mapped plausibly.

5. Select `Plugins → GoReSym → Import JSON`, then choose `goresym.json` in the file dialog.

6. Wait for the stage-based background import to complete.

7. Select `Plugins → GoReSym → Show Imported Metadata` to review the Go versions, build ID, modules and replacements, dependencies, build settings, source paths, runtime addresses, import counts, and diagnostics.

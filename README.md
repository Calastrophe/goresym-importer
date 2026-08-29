# GoReSym Importer

A Binary Ninja plugin that validates [GoReSym](https://github.com/mandiant/GoReSym) JSON output and applies recovered functions and strings.

## How to Use

1. Copy this directory into Binary Ninja's user plugin directory. If installing the plugin manually, install its Python dependency with the Python environment configured in Binary Ninja:

   ```console
   python -m pip install -r /path/to/goresym-importer/requirements.txt
   ```

2. Download or build [GoReSym](https://github.com/mandiant/GoReSym).

3. Generate JSON for the [Go](https://go.dev/) binary. The `-d` flag includes standard-library functions and `-strings` recovers strings:

   ```console
   GoReSym -d -strings /path/to/binary > /path/to/goresym.json
   ```

4. Open the same binary in Binary Ninja. The importer expects the GoReSym addresses to match the Binary View, so use the binary's original image base.

5. Select `Plugins → GoReSym → Import JSON`, then choose `goresym.json` in the file dialog.

6. Wait for the background import to complete. The number of imported user functions, standard-library functions, strings, created components, and skipped entries are logged.

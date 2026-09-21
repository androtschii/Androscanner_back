# Запуск backend на Windows с путём к Pango/cairo из MSYS2 — без него
# WeasyPrint падает с "cannot load library 'libgobject-2.0-0'", потому что
# сами DLL в системный PATH не попадают при установке через pacman.
#
# Использование:
#   .\run-dev.ps1                          # обычный запуск, BackgroundTasks
#   $env:USE_CELERY="true"; .\run-dev.ps1  # с очередью (нужен воркер Celery отдельно)

$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
$env:PYTHONIOENCODING = "utf-8"

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $venvPython -m uvicorn app.main:app --host 0.0.0.0 --port 8000

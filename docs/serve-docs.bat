@echo off
REM Build and serve MkDocs documentation locally (Windows)

echo Building and serving pyMC_Core documentation...
echo ============================================
echo.

REM Check if we're in the docs directory
if not exist "mkdocs.yml" (
    echo Error: mkdocs.yml not found. Please run this script from the docs\ directory.
    pause
    exit /b 1
)

REM Install dependencies if requirements.txt exists
if exist "requirements.txt" (
    echo Installing documentation dependencies...
    pip install -r requirements.txt
    echo.
)

REM Build the documentation
echo Building documentation...
python -m mkdocs build --clean
echo.

REM Serve the documentation
echo Starting local server at http://localhost:8000
echo Press Ctrl+C to stop the server
echo.
python -m mkdocs serve

@echo off
REM DevilWare OSINT Tool Batch Script - Pre Release Version
REM Usage: osint.bat [type] [query] [options]
REM Or run without arguments for interactive menu

REM Activate virtual environment
call .venv\Scripts\activate.bat

REM Run the Python script with all passed arguments
python osint_tool.py %*

REM Deactivate virtual environment
call deactivate
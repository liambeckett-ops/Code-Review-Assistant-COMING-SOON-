# Code Review Assistant

A simple Python CLI tool to help you review Python code files for common issues and provide suggestions.

## Features
- Checks for long lines, tabs vs spaces, trailing whitespace, and indentation
- PEP8 naming convention checks for functions and classes
- Detects TODO/FIXME comments
- Finds duplicate code blocks
- Detects unused imports and variables
- Checks for missing docstrings
- Warns about long or complex functions
- Option to auto-fix trailing whitespace

## Usage
1. Run the assistant:
   ```sh
   python code_review_assistant.py
   ```
2. Enter the path to a Python file to review, or type `exit` to quit.
3. To auto-fix trailing whitespace, type:
   ```
   fix <file path>
   ```

## Example
```
File path or command: example.py

Reviewing example.py...
Line 10: Exceeds 79 characters.
Line 15: Contains a tab character. Use spaces instead.
Function 'myFunction' should be snake_case (PEP8).
...
Review complete.
```

## Requirements
- Python 3.7 or higher

---
Feel free to expand this tool with more checks or features!
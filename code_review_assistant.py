#Code Review Assistant - Simple Python CLI
#This tool will help you review Python code files for common issues and provide suggestions.

import os
import sys
import ast
import re

def main():
    print("Welcome to the Code Review Assistant!")
    print("Enter the path to a Python file to review, or 'exit' to quit.")
    print("Type 'fix <file path>' to auto-fix simple issues (trailing whitespace).\n")
    while True:
        user_input = input("File path or command: ").strip()
        if user_input.lower() == 'exit':
            print("Goodbye!")
            break
        if user_input.lower().startswith('fix '):
            file_path = user_input[4:].strip()
            if not os.path.isfile(file_path):
                print("File not found. Please try again.")
                continue
            auto_fix_trailing_whitespace(file_path)
            print(f"Trailing whitespace removed in {file_path}.")
            continue
        file_path = user_input
        if not os.path.isfile(file_path):
            print("File not found. Please try again.")
            continue
        review_file(file_path)
def auto_fix_trailing_whitespace(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    fixed_lines = [line.rstrip(' \t\r\n') + ('\n' if line.endswith('\n') else '') for line in lines]
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(fixed_lines)
def check_duplicate_code_blocks(lines, block_size=5):
    """
    Detects duplicate code blocks of a given size (default 5 lines).
    """
    from collections import defaultdict
    hashes = defaultdict(list)
    for i in range(len(lines) - block_size + 1):
        block = ''.join([l.strip() for l in lines[i:i+block_size]])
        if block:
            hashes[block].append(i+1)
    for block, occurrences in hashes.items():
        if len(occurrences) > 1:
            print(f"Duplicate code block detected at lines: {', '.join(map(str, occurrences))} (block size: {block_size})")
def review_file(file_path):
    print(f"\nReviewing {file_path}...")
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    # Simple checks
    check_long_lines(lines)
    check_tabs_vs_spaces(lines)
    check_trailing_whitespace(lines)
    check_indentation(lines)
    check_pep8_naming(lines)
    check_todo_fixme_comments(lines)
    check_duplicate_code_blocks(lines)
    check_unused_imports_and_variables(file_path)
    check_missing_docstrings(file_path)
    check_function_length_and_complexity(file_path)
    print("\nReview complete.\n")
    print(f"\nReviewing {file_path}...")
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    # Simple checks
    check_long_lines(lines)
    check_tabs_vs_spaces(lines)
    check_trailing_whitespace(lines)
    check_indentation(lines)
    check_pep8_naming(lines)
    check_todo_fixme_comments(lines)
    check_duplicate_code_blocks(lines)
    check_unused_imports_and_variables(file_path)
    check_missing_docstrings(file_path)
    check_function_length_and_complexity(file_path)
    print("\nReview complete.\n")

import ast

def check_todo_fixme_comments(lines):
    for i, line in enumerate(lines, 1):
        if 'TODO' in line or 'FIXME' in line:
            print(f"Line {i}: Contains TODO/FIXME comment.")

def check_function_length_and_complexity(file_path, max_length=50, max_complexity=10):
    with open(file_path, 'r', encoding='utf-8') as f:
        source = f.read()
    tree = ast.parse(source, filename=file_path)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Function length
            start = node.lineno
            end = max([n.lineno for n in ast.walk(node) if hasattr(n, 'lineno')], default=start)
            length = end - start + 1
            if length > max_length:
                print(f"Function '{node.name}' is {length} lines long (>{max_length}) (line {start}).")
            # Cyclomatic complexity (basic count of branches)
            complexity = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.For, ast.While, ast.And, ast.Or, ast.ExceptHandler, ast.With, ast.Try, ast.BoolOp, ast.IfExp)):
                    complexity += 1
            if complexity > max_complexity:
                print(f"Function '{node.name}' has cyclomatic complexity {complexity} (>{max_complexity}) (line {start}).")

def check_missing_docstrings(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read(), filename=file_path)
    # Check module docstring
    if ast.get_docstring(tree) is None:
        print("Module is missing a docstring.")
    # Check classes and functions
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if ast.get_docstring(node) is None:
                kind = 'Function' if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else 'Class'
                print(f"{kind} '{node.name}' is missing a docstring (line {node.lineno}).")

def check_unused_imports_and_variables(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read(), filename=file_path)
    assigned = set()
    used = set()
    imports = set()
    class ImportVisitor(ast.NodeVisitor):
        def visit_Import(self, node):
            for alias in node.names:
                imports.add(alias.asname or alias.name)
        def visit_ImportFrom(self, node):
            for alias in node.names:
                imports.add(alias.asname or alias.name)
    class NameVisitor(ast.NodeVisitor):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Store):
                assigned.add(node.id)
            elif isinstance(node.ctx, ast.Load):
                used.add(node.id)
    ImportVisitor().visit(tree)
    NameVisitor().visit(tree)
    unused_imports = imports - used
    unused_vars = assigned - used - imports
    for name in unused_imports:
        print(f"Unused import detected: '{name}'")
    for name in unused_vars:
        if not name.startswith('_'):
            print(f"Unused variable detected: '{name}'")

def check_long_lines(lines, max_length=79):
    for i, line in enumerate(lines, 1):
        if len(line.rstrip('\n')) > max_length:
            print(f"Line {i}: Exceeds {max_length} characters.")

def check_tabs_vs_spaces(lines):
    for i, line in enumerate(lines, 1):
        if '\t' in line:
            print(f"Line {i}: Contains a tab character. Use spaces instead.")

def check_trailing_whitespace(lines):
    for i, line in enumerate(lines, 1):
        if line.rstrip('\n').rstrip(' ') != line.rstrip('\n'):
            print(f"Line {i}: Trailing whitespace detected.")

def check_indentation(lines):
    for i, line in enumerate(lines, 1):
        if line.startswith(' '):
            spaces = len(line) - len(line.lstrip(' '))
            if spaces % 4 != 0:
                print(f"Line {i}: Indentation is not a multiple of 4 spaces.")

import re
def check_pep8_naming(lines):
    func_pattern = re.compile(r'^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)')
    class_pattern = re.compile(r'^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)')
    for i, line in enumerate(lines, 1):
        func_match = func_pattern.match(line)
        if func_match:
            name = func_match.group(1)
            if not re.match(r'^[a-z_][a-z0-9_]*$', name):
                print(f"Line {i}: Function '{name}' should be snake_case (PEP8).")
        class_match = class_pattern.match(line)
        if class_match:
            name = class_match.group(1)
            if not re.match(r'^[A-Z][A-Za-z0-9]*$', name):
                print(f"Line {i}: Class '{name}' should be CamelCase (PEP8).")

if __name__ == "__main__":
    main()
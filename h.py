#!/usr/bin/env python
import ast

with open('tests/test_cli.py') as f:
    code = ast.parse(f.read())

for node in ast.walk(code):
    if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)):
        docstring = ast.get_docstring(node)
        if docstring:
            print(docstring)
            # print(repr(docstring))

# Usage:
#   python h.py > h.bat
#   h

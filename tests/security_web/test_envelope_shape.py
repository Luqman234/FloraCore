"""Reproduce source-snapshot input bug locally. No network/database/key access."""
import ast
import subprocess
from types import SimpleNamespace
request = SimpleNamespace()
def jsonify(**kwargs):
    return kwargs

source = subprocess.check_output(['git', 'show', 'origin/website:floraos_device_api.py'], text=True)
node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'device_message')
node.decorator_list = []
# Execute the real function body, but restrict tests to its first input/version gate.
ns = dict(request=request, jsonify=jsonify, PROTOCOL_VERSION=1)
exec(compile(ast.Module(body=[node], type_ignores=[]), 'floraos_device_api.py', 'exec'), ns)
for value in ({}, [], None, [1], 'non-object', 7, True):
    request.get_json = lambda silent=True: value
    try:
        result = ns['device_message']()
    except AttributeError:
        assert value in ([1], 'non-object', 7, True)
        print(f'CONFIRMED: {type(value).__name__} causes unhandled AttributeError before authentication')
    else:
        assert result[1] == 400
        print(f'PASS: {type(value).__name__} rejected with 400')

from __future__ import annotations

PYTHON_EXTENSIONS = {".py"}
JS_TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}

SUPPORTED_EXTENSIONS = PYTHON_EXTENSIONS | JS_TS_EXTENSIONS

SEVERITY_BY_CLASS = {
    "sql-injection": "high",
    "command-injection": "high",
    "path-traversal": "medium",
}

PYTHON_REQUEST_MARKERS = (
    "request.args",
    "request.form",
    "request.json",
    "request.get_json",
    "request.files",
    "request.GET",
    "request.POST",
    "request.body",
    "request.FILES",
    "query_params",
)

JS_REQUEST_MARKERS = (
    "req.query",
    "req.params",
    "req.body",
    "req.files",
    "ctx.query",
    "ctx.params",
    "ctx.request.body",
    "searchParams",
    "request.json",
)

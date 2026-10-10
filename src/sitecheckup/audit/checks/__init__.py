"""Built-in checks. Importing this package registers all of them, in report order."""

from importlib import import_module

for _module in ("transport", "headers", "cookies", "exposed", "wordpress", "hygiene"):
    import_module(f"{__name__}.{_module}")

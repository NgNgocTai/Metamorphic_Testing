"""Importing this package imports every sibling module, so each `@implements(...)` class registers itself."""
import importlib
import pkgutil

for _m in pkgutil.iter_modules(__path__):
    importlib.import_module(f"{__name__}.{_m.name}")

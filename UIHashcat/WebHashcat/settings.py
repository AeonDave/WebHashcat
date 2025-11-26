"""Django settings loader that reuses the docker template in any environment."""
import importlib.machinery
import os
import types

_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "settings.py.docker")
_loader = importlib.machinery.SourceFileLoader("webhashcat_settings_template", _TEMPLATE_PATH)
_module = types.ModuleType(_loader.name)
_module.__file__ = _TEMPLATE_PATH
_loader.exec_module(_module)

globals().update({name: getattr(_module, name) for name in dir(_module) if name.isupper()})

import os
import importlib.util


def load_modules():
    modules = {}
    base_path = os.path.join(os.path.dirname(__file__), "..", "modules")
    base_path = os.path.abspath(base_path)

    for file_name in os.listdir(base_path):
        if not file_name.endswith(".py"):
            continue

        module_path = os.path.join(base_path, file_name)
        module_id = file_name[:-3]

        spec = importlib.util.spec_from_file_location(module_id, module_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        module_key = getattr(mod, "module_key", None)
        module_name = getattr(mod, "module_name", module_id)
        cli_name = getattr(mod, "cli_name", module_id)

        if module_key is None:
            continue

        modules[str(module_key)] = {
            "id": module_id,
            "name": module_name,
            "cli_name": cli_name,
            "run_tui": getattr(mod, "run_tui", None),
            "register_args": getattr(mod, "register_args", None),
            "run_cli": getattr(mod, "run_cli", None),
        }

    return modules


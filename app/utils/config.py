# config_manager.py

import json
from pathlib import Path

class ConfigManager:
    """
    Handles loading and saving the OpenAI API key
    to a per-user config file in the home directory.
    """
    def __init__(self):
        # on Windows: %USERPROFILE%\.procsentinel\config.json
        # on *nix:     ~/.procsentinel/config.json
        self.config_path = Path.home() / ".procsentinel" / "config.json"

    def load_key(self) -> str:
        """Return the saved API key, or empty string if none."""
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
            return data.get("OPENAI_API_KEY", "")
        except FileNotFoundError:
            return ""
        except Exception:
            return ""

    def save_key(self, key: str):
        """Persist the API key to disk."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"OPENAI_API_KEY": key}
        self.config_path.write_text(json.dumps(payload), encoding="utf-8")

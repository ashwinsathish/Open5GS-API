from typing import Any

class Open5GSError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class ConfigurationError(Open5GSError):
    def __init__(self, message: str, invalid_value: Any = None, allowed_values: Any = None):
        self.invalid_value = invalid_value
        self.allowed_values = allowed_values
        super().__init__(f"Configuration Error: {message}")

class CommunicationError(Open5GSError):
    def __init__(self, message: str, endpoint: str = None):
        self.endpoint = endpoint
        super().__init__(f"Communication Error: {message}")

class ValidationError(Open5GSError):
    def __init__(self, message: str, field: str, invalid_value: Any, allowed_values: Any = None):
        self.field = field
        self.invalid_value = invalid_value
        self.allowed_values = allowed_values
        super().__init__(f"Validation Error: {message}")
__version__ = "0.15.2" 

from .core import Open5GS
from .exceptions import ConfigurationError, CommunicationError, ValidationError

open5gs = Open5GS()

__all__ = ['open5gs', 'ConfigurationError', 'CommunicationError', 'ValidationError']
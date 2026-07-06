"""
Shared Limiter instance. Lives in its own module (not main.py) so routers can
import it without a circular import — main.py imports the routers, so the
routers can't import the Limiter back from main.py.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

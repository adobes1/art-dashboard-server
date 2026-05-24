from api.kerberos import do_kinit
import functools
import time
import threading

_last_kinit = 0.0
_kinit_lock = threading.Lock()
KINIT_INTERVAL_SECONDS = 60


def update_keytab(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        global _last_kinit
        now = time.monotonic()
        if now - _last_kinit >= KINIT_INTERVAL_SECONDS:
            with _kinit_lock:
                if now - _last_kinit >= KINIT_INTERVAL_SECONDS:
                    do_kinit()
                    _last_kinit = time.monotonic()
        return func(*args, **kwargs)
    return wrapper

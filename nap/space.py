"""Hugging Face Space process: API plus continuous global sentinel."""
import os, threading
from .api import serve
from .storage import Store
from .world_guard import watch_public

def main():
    db=os.getenv("NAP_DB_PATH", "/data/archon-sigilagi.db")
    threading.Thread(target=watch_public, kwargs={"store":Store(db), "interval_seconds":int(os.getenv("ARCHON_SCAN_INTERVAL", "900"))}, daemon=True, name="global-sentinel").start()
    serve()

if __name__ == "__main__": main()

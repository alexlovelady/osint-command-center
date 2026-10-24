"""PyInstaller entry point: package-qualified import so the relative imports inside osintcc resolve."""
import multiprocessing

from osintcc.server import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()

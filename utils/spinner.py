import sys
import time
import threading


class Spinner:
    def __init__(self, message="Loading"):
        self.message = message
        self.spinner_chars = ['|', '/', '-', '\\']
        self.running = False
        self.thread = None
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        sys.stdout.write('\r' + ' ' * (len(self.message) + 20) + '\r')
        sys.stdout.flush()
    
    def _spin(self):
        i = 0
        while self.running:
            sys.stdout.write(f'\r{self.message} {self.spinner_chars[i % len(self.spinner_chars)]}')
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1


def print_progress(step, total, message):
    sys.stdout.write(f'\r[{step}/{total}] {message}...')
    sys.stdout.flush()
    if step == total:
        print()


def loading_dots(text="Loading"):
    """Prints loading dots animation"""
    for _ in range(3):
        sys.stdout.write('.')
        sys.stdout.flush()
        time.sleep(0.5)
    print()

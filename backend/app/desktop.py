import sys, time, webbrowser, threading
from pathlib import Path

if getattr(sys, 'frozen', False):
    sys.path.insert(0, str(Path(sys._MEIPASS)))
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

def open_browser():
    time.sleep(2)
    webbrowser.open('http://127.0.0.1:8000')

def main():
    print('=' * 60)
    print('  ERROR-PANEL v2.0.0 - Mission Control')
    print('=' * 60)
    print('Server: http://127.0.0.1:8000')
    print('Press Ctrl+C to stop')

    threading.Thread(target=open_browser, daemon=True).start()

    import uvicorn
    uvicorn.run('backend.app.main:app', host='127.0.0.1', port=8000, log_level='info')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Shutting down...')

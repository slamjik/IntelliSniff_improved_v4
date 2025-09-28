import argparse, uvicorn
from . import api, capture, train_model
def main():
    p = argparse.ArgumentParser()
    p.add_argument('cmd', nargs='?', default='serve')
    args = p.parse_args()
    if args.cmd == 'serve':
        uvicorn.run('traffic_analyzer.api:app', host='0.0.0.0', port=8000, reload=False)
    elif args.cmd == 'start_capture':
        capture.start_capture()
    elif args.cmd == 'stop_capture':
        capture.stop_capture()
    elif args.cmd == 'train_model':
        import traffic_analyzer.train_model as t; t.__main__ = True; t.main() if hasattr(t,'main') else None
    else:
        print('Unknown command', args.cmd)

if __name__ == '__main__':
    main()

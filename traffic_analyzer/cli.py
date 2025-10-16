import argparse

import uvicorn

from . import capture


def main(argv=None):
    parser = argparse.ArgumentParser(description="IntelliSniff CLI")
    parser.add_argument(
        "cmd",
        nargs="?",
        default="serve",
        choices=["serve", "start_capture", "stop_capture", "train_model"],
        help="Команда: serve/start_capture/stop_capture/train_model",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Хост для API (только для serve)")
    parser.add_argument("--port", type=int, default=8000, help="Порт для API (только для serve)")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Для train_model: обучить демо-модель вместо реального датасета",
    )
    args = parser.parse_args(argv)

    if args.cmd == "serve":
        uvicorn.run("traffic_analyzer.api:app", host=args.host, port=args.port, reload=False)
    elif args.cmd == "start_capture":
        capture.start_capture()
    elif args.cmd == "stop_capture":
        capture.stop_capture()
    elif args.cmd == "train_model":
        from . import train_model as tm

        try:
            if args.demo:
                tm.train_demo_model()
            else:
                tm.train_from_dataset()
        except FileNotFoundError as exc:
            parser.error(str(exc))
    else:
        parser.error(f"Unknown command: {args.cmd}")


if __name__ == "__main__":
    main()

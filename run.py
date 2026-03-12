import threading
import uvicorn

from flask_app.app import app as flask_app
from fastapi_backend.api import app as fastapi_app


def run_flask():
    """
    Starts the Flask dashboard server
    """
    flask_app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )


def run_fastapi():
    """
    Starts the FastAPI backend server
    """
    uvicorn.run(
        fastapi_app,
        host="0.0.0.0",
        port=8000
    )


if __name__ == "__main__":

    # Start Flask and FastAPI in parallel
    flask_thread = threading.Thread(target=run_flask)
    fastapi_thread = threading.Thread(target=run_fastapi)

    flask_thread.start()
    fastapi_thread.start()
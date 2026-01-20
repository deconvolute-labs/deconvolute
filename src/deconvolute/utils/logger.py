import logging

logger = logging.getLogger("deconvolute")

# Add NullHandler to prevent logging warnings if the application
# doesn't configure logging.
logger.addHandler(logging.NullHandler())


def get_logger(name: str | None = None) -> logging.Logger:
    if name:
        return logger.getChild(name)
    return logger

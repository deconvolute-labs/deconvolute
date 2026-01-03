import logging

logger = logging.getLogger("deconvolute")

# Add NullHandler to prevent logging warnings if the application
# doesn't configure logging.
logger.addHandler(logging.NullHandler())


def get_logger() -> logging.Logger:
    return logger

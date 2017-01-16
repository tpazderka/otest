import logging
import os

SERVER_LOG_FOLDER = "server_log"


def setup_logging(logfile, log):
    hdlr = logging.FileHandler(logfile)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")

    hdlr.setFormatter(base_formatter)
    log.addHandler(hdlr)
    log.setLevel(logging.DEBUG)


def not_logging(logfile, logger):
    hdlr = logging.FileHandler(logfile)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")

    hdlr.setFormatter(base_formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)


def get_test_info(session, test_id):
    return session["test_info"][test_id]


def setup_common_log():
    common_logger = logging.getLogger("common")
    hdlr = logging.FileHandler("%s/common.log" % SERVER_LOG_FOLDER)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")
    hdlr.setFormatter(base_formatter)
    common_logger.addHandler(hdlr)
    common_logger.setLevel(logging.DEBUG)

    return common_logger, hdlr, base_formatter


def with_or_without_slash(path):
    if os.path.isdir(path):
        return path

    if path.endswith("%2F"):
        path = path[:-3]
        if os.path.isdir(path):
            return path
    else:
        path += "%2F"
        if os.path.isdir(path):
            return path

    return None

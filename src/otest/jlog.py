import json


class JLog(object):
    def __init__(self, logger, sid):
        self.logger = logger
        self.id = sid

    def info(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.info(json.dumps(_dict))

    def debug(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.debug(json.dumps(_dict))

    def exception(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.exception(json.dumps(_dict))

    def error(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.error(json.dumps(_dict))

    def warning(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.warning(json.dumps(_dict))
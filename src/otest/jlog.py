import json


class JLog(object):
    def __init__(self, logger, sid, tag='JLOG'):
        self.logger = logger
        self.id = sid
        self.tag = tag

    def _msg(self, info):
        return '<<{}:{}>> {}'.format(self.tag, self.id, json.dumps(info))

    def info(self, info):
        self.logger.info(self._msg(info))

    def debug(self, info):
        self.logger.debug(self._msg(info))

    def exception(self, info):
        self.logger.exception(self._msg(info))

    def error(self, info):
        self.logger.error(self._msg(info))

    def warning(self, info):
        self.logger.warning(self._msg(info))
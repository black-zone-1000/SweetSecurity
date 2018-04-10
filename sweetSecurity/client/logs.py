import logging

def setup():
	LOG_FILENAME='/var/log/sweetsecurity.log'
	logger = logging.getLogger('SweetSecurityLogger')
	logger.setLevel(logging.INFO) 
	handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=100000, backupCount=1)
	handler.setFormatter(logging.Formatter("%(asctime)s: %(pathname)s:%(lineno)d -  %(message)s"))
	logger.addHandler(handler)
	return logger

import logging

import datetime
def setup_logging():
    logger = logging.getLogger('network_scanner')
    logger.setLevel(logging.INFO)
    log_file = '/var/log/network_scanner.log'
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    log_format = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(log_format)
    logger.addHandler(file_handler)
    return logger
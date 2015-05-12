import logging
import os

class OnlyTestsFilter(logging.Filter):

    def filter(self, record):
        
        file_path = os.path.realpath(__file__)
        dir_path = os.path.dirname(file_path)
        dir_members = os.listdir(dir_path)
        files = []
        for filename in dir_members:
            split_file = filename.split(".")
            if len(split_file) > 1 and split_file[1] == 'py':
                files.append(os.path.join(split_file[0]))

        should_show = True
        
        for python_file in files:
            if python_file in record.getMessage():
                should_show = False
        
        return should_show




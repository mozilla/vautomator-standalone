import abc


# This is an abstract class
class Task(metaclass=abc.ABCMeta):
    # One target will have at least one task
    # One task will have one target at a time
    # self.tasktarget here is a Target object
    def __init__(self, target_obj):
        self.tasktarget = target_obj

    @abc.abstractmethod
    def run(self):
        pass

    


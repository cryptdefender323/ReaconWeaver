from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import time

class ProgressManager:
    def __init__(self):
        self.progress = Progress(
            SpinnerColumn(),
            BarColumn(),
            TextColumn("[progress.description]{task.description}"),
        )
        self.tasks = {}

    def start_task(self, task_name):
        task = self.progress.add_task(task_name, total=None)
        self.tasks[task_name] = task
        self.progress.start()
        return task

    def update_task(self, task_name, completed=None):
        if task_name in self.tasks:
            task = self.tasks[task_name]
            if completed is not None:
                self.progress.update(task, completed=completed)
            else:
                self.progress.update(task, advance=1)

    def stop_task(self, task_name):
        if task_name in self.tasks:
            self.progress.stop_task(self.tasks[task_name])
            del self.tasks[task_name]

    def finish(self):
        self.progress.stop()
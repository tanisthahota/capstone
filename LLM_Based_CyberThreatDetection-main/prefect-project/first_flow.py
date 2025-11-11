from prefect import flow, task

@task
def my_simple_task():
    """A task that just says hello."""
    print("Hello from your first Prefect task! 👋")

@flow(log_prints=True)
def my_first_flow():
    """A flow that calls our simple task."""
    print("Flow is starting...")
    my_simple_task()
    print("Flow has finished!")

if __name__ == "__main__":
    my_first_flow()

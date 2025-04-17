import os


def pytest_configure():
    os.environ["NOT_MY_KEY"] = "my_32_byte_secret_key_example!!"

import os

from dotenv import load_dotenv

load_dotenv()


def get_config() -> dict:
    return {
        "TEST_DISCO_ADDRESS": os.environ["TEST_DISCO_ADDRESS"],
        "TEST_JWKS_ADDRESS": os.environ["TEST_JWKS_ADDRESS"],
        "TEST_CLIENT_ID": os.environ["TEST_CLIENT_ID"],
        "TEST_CLIENT_SECRET": os.environ["TEST_CLIENT_SECRET"],
        "TEST_SCOPE": os.environ["TEST_SCOPE"],
        "TEST_EXPIRED_TOKEN": os.environ["TEST_EXPIRED_TOKEN"],
        "TEST_AUDIENCE": os.environ["TEST_AUDIENCE"],
    }

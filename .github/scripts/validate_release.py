"""
This script is used to validate if the version is the same of one of the previous versions.
"""

import os
import sys
import traceback
import configparser
from http import HTTPStatus
import requests
from dotenv import load_dotenv


def main() -> None:
    """
    Verify if the version is the same of one of the previous versions.

    Returns:
    - None
    """
    token = os.getenv("GH_API_TOKEN")
    user_repo = os.getenv("GITHUB_REPOSITORY")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    releases = f"https://api.github.com/repos/{user_repo}/releases"
    response = requests.get(releases, headers=headers, timeout=20)
    response_body: list[dict[str, any]] = response.json()
    if response.status_code == HTTPStatus.OK.value:
        previous_versions = [release.get("tag_name")[1:] for release in response_body]  # example: ['1.0.0']
        root = os.getenv("GITHUB_WORKSPACE")
        config = configparser.ConfigParser()
        config.read(f"{root}/setup.cfg")
        actual_version = config.get("metadata", "version")
        if actual_version in previous_versions:
            print("\033[33m The version is the same of one of the previous versions, please update the version \033[0m")
            sys.exit(1)
    else:
        print(f"\033[33m Something went wrong getting the releases: {response_body} \033[0m")
        sys.exit(1)

def load_env_vars() -> None:
    """
    Load the environment variables from .env file.

    Returns:
    - None
    """
    try:
        if os.path.exists("vars.env"):
            load_dotenv("vars.env")
            print("\033[92m The vars.env file loaded \033[0m")
        else:
            raise FileNotFoundError
    except FileNotFoundError:
        print("\033[33m The vars.env file was not found, using env vars of github action \033[0m")

if __name__ == "__main__":
    try:
        load_env_vars()
        ENVIRONMENT = ""
        destiny_branch = os.getenv("GITHUB_BASE_REF")
        if destiny_branch == "master":
            ENVIRONMENT = "PRD"
        elif destiny_branch == "development":
            ENVIRONMENT = destiny_branch.upper()
        else:
            print("\033[92m The destiny branch is not master or dev, script doesnt need to run \033[0m")
        if ENVIRONMENT == "PRD":
            main()
        else:
            print("\033[92m PR destiny is not to dev, skipping the execution of this code \033[0m")
    except Exception:
        print(f"\033[33m Complete exception traceback: {traceback.format_exc()} \033[0m")
        sys.exit(1)
    else:
        print("\033[92m The release version is valid \033[0m")
    finally:
        print("\033[92m End of the script \033[0m")

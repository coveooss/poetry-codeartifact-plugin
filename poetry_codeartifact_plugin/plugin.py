import os
import re
from urllib.parse import urlparse

import boto3

from botocore.exceptions import BotoCoreError
from cleo.io.io import IO
from poetry.config.config import Config
from poetry.exceptions import PoetryException
from poetry.plugins import Plugin
from poetry.poetry import Poetry
from poetry.utils.authenticator import Authenticator

RE_CODEARTIFACT_NETLOC = re.compile(
    r"^([a-z][a-z-]*)-(\d+)\.d\.codeartifact\.[^.]+\.amazonaws\.com$"
)

RUNNING_ON_WINDOWS = os.name == 'nt'

def monkeypatch_authenticator(io: IO):
    old_request = Authenticator.request

    def new_request(self: Authenticator, method, url, *args, **kwargs):
        new_kwargs = kwargs.copy()
        raise_for_status = new_kwargs.pop("raise_for_status", None)
        new_kwargs["raise_for_status"] = False

        response = old_request(self, method, url, *args, **new_kwargs)

        if response.status_code in (401, 403):
            netloc = urlparse(response.url)[1]
            m = RE_CODEARTIFACT_NETLOC.match(netloc)
            if m:
                domain, domain_owner = m.groups()
                config = self.get_repository_config_for_url(url)
                if config:
                    io.write_line(
                        f"\nGetting new CodeArtifact authorization token for repo {config.name} ({domain=}, {domain_owner=})..."
                    )
                    try:
                        response = boto3.client("codeartifact").get_authorization_token(
                            domain=domain,
                            domainOwner=domain_owner,
                        )
                    except BotoCoreError as err:
                        raise PoetryException(
                            f"Failed to get a new CodeArtifact authorization token: {err}\n\n-> Are your local AWS credentials up-to-date?"
                        )

                    try:
                        self._password_manager.set_http_password(
                            config.name, "aws", response["authorizationToken"]
                        )
                    except Exception as ex:
                        io.write_line(f"\nFailed to store CodeArtifact authorization token: \n{super(type(ex))}\n{ex}\n{ex.__dict__}")
                        if RUNNING_ON_WINDOWS:
                            # hack to bypass the keyring which only accepts 1280 chars on windows (token is 1700+)
                            set_password_without_keyring(self, response["authorizationToken"], config.name)
                        else:
                            raise PoetryException(
                                f"Failed to store CodeArtifact authorization token: {ex}"
                            )

                    else:
                        self._password_manager.set_http_password(
                            config.name, "aws", response["authorizationToken"]
                        )

                    self.reset_credentials_cache()
                    self._password_manager._config = Config.create(reload=True)

                    # Retry the request now that we're authenticated
                    return old_request(self, method, url, *args, **kwargs)

        if raise_for_status:
            response.raise_for_status()
        return response

    Authenticator.request = new_request


def set_password_without_keyring(self: Authenticator, token: str, repository: str) -> None:
    # see:
    # - https://github.com/python-poetry/poetry/issues/6597
    # - https://github.com/jaraco/keyring/issues/540
    self._password_manager.warn_plaintext_credentials_stored()
    self._config.auth_config_source.add_property(
        f"http-basic.{repository}",
        {"username": "aws", "password": token}
    )


class CodeArtifactPlugin(Plugin):
    def activate(self, poetry: Poetry, io: IO) -> None:
        monkeypatch_authenticator(io)

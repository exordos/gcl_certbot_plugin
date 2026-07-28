#    Copyright 2025 Genesis Corporation.
#
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging

from certbot import errors
from certbot.plugins import dns_common
from gcl_sdk.clients.http import base as core_client_base

from gcl_certbot_plugin import clients as dns_clients

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Authenticator(dns_common.DNSAuthenticator):
    description = "Obtain certificates with Genesis Core DNS server"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._records_to_cleanup_map = {}

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super().add_parser_arguments(add, default_propagation_seconds=0)
        add(
            "endpoint",
            help="Core API endpoint.",
            default="http://core.local.genesis-core.tech:11010",
        )
        add("login", help="Core API login.")
        add("password", help="Core API password.")

    def _setup_credentials(self):
        if not all((self.conf("login"), self.conf("password"))):
            raise errors.MisconfigurationError(
                "Credentials are not configured, please set --genesis-core-login and --genesis-core-password"
            )
        auth = core_client_base.CoreIamAuthenticator(
            self.conf("endpoint"), self.conf("login"), self.conf("password")
        )
        self.dns_client = dns_clients.TinyDNSCoreClient(
            base_url=self.conf("endpoint"), auth=auth
        )

        # Check credentials here to minimize other requests.
        domains_collection = "/v1/dns/domains/"
        self.dns_client.domains.filter(domains_collection)

    def more_info(self):
        return "This plugin uses integrated Genesis Core DNS server to perform DNS-01 checks."

    def _perform(self, domain, validation_name, validation):
        record = self.dns_client.create_txt_record(
            domain, validation, "_acme-challenge"
        )

        self._records_to_cleanup_map[(domain, validation_name, validation)] = record

    def _cleanup(self, domain, validation_name, validation):
        record = self._records_to_cleanup_map.pop((domain, validation_name, validation))

        self.dns_client.delete_record(record["domain"].split("/")[-1], record["uuid"])

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
import typing as tp
import uuid as sys_uuid

import bazooka
from gcl_sdk.clients.http import base


class TinyDNSCoreClient:
    def __init__(
        self,
        base_url: str,
        http_client: bazooka.Client | None = None,
        auth: base.AbstractAuthenticator | None = None,
    ) -> None:
        http_client = http_client or bazooka.Client()
        self._http_client = http_client
        self._base_url = base_url
        self._auth = auth
        self._domains_client = base.CollectionBaseClient(
            self._base_url, self._http_client, self._auth
        )
        self._records_client = base.CollectionBaseClient(
            self._base_url, self._http_client, self._auth
        )

    @property
    def domains(self) -> base.CollectionBaseClient:
        return self._domains_client

    @property
    def records(self) -> base.CollectionBaseClient:
        return self._records_client

    def create_txt_record(
        self, domain: str, content: str, prefix: str = ""
    ) -> dict[str, tp.Any]:
        parent_domain = domain
        domains_collection = "/v1/dns/domains/"

        # Try to find target zone iteratively.
        while parent_domain:
            try:
                parent_domain = parent_domain.split(".", 1)[1]
            except IndexError:
                raise ValueError(f"Could not find DNS zone for domain {domain}")

            domains = self.domains.filter(domains_collection, name=parent_domain)
            if domains:
                name = domain[: -len(parent_domain)]
                zone = domains[0]
                break

        if prefix:
            name = f"{prefix}.{name}"

        data = {
            "type": "TXT",
            "ttl": 0,
            "record": {
                "kind": "TXT",
                "name": name,
                "content": content,
            },
        }

        records_collection = f"/v1/dns/domains/{zone['uuid']}/records/"
        return self.records.create(records_collection, data)

    def delete_record(self, domain: sys_uuid.UUID, record: sys_uuid.UUID) -> None:
        records_collection = f"/v1/dns/domains/{domain}/records/"
        self.records.delete(records_collection, record)

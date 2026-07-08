#!/usr/bin/env python3

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
import argparse

from cryptography import x509
from gcl_sdk.clients.http import base as core_client_base

from gcl_certbot_plugin import acme
from gcl_certbot_plugin import clients as dns_clients

DEFAULT_PRIVATE_KEY_PATH = "/etc/exordos_core/certbot/privkey.pem"


def issue_cert_dns_core(
    domains: list[str],
    email: str,
    dns_client: dns_clients.TinyDNSCoreClient,
    private_key_path: str = DEFAULT_PRIVATE_KEY_PATH,
) -> None:
    """A simple example to issue a cert via Genesis Core DNS."""
    private_key = acme.get_or_create_client_private_key(private_key_path)

    print(f"Loaded private key from: {private_key_path}")

    client_acme = acme.get_acme_client(private_key, email)

    print(f"The ACME client is ready: {client_acme}")

    pkey_pem, csr_pem, fullchain_pem = acme.create_cert(
        client_acme,
        dns_client,
        domains,
    )

    print("The cert generated!")
    print("============ pkey ===============")
    print(pkey_pem.decode())
    print("=========== csr_pem ===============")
    print(csr_pem.decode())
    print("============ fullchain ===============")
    print(fullchain_pem)
    print("============ valid ===============")
    cert = x509.load_pem_x509_certificate(fullchain_pem.encode())
    print("Before: ", cert.not_valid_before_utc.isoformat())
    print("After: ", cert.not_valid_after_utc.isoformat())


if __name__ == "__main__":
    """A simple example to issue a cert via Genesis Core DNS.
    
    Usage:

    python create_cert.py \
        --domain test.pdns.your.domain \
        --email infra@exordos.com \
        --endpoint http://10.20.0.2:80/api/core \
        --core-user test \
        --core-password test
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", type=str, required=True)
    parser.add_argument("--email", type=str, required=True)
    parser.add_argument("-l", "--endpoint", type=str, required=True)
    parser.add_argument("-u", "--core-user", type=str, required=True)
    parser.add_argument("-p", "--core-password", type=str, required=True)
    parser.add_argument(
        "--private-key-path", type=str, default=DEFAULT_PRIVATE_KEY_PATH
    )
    args = parser.parse_args()

    domains = [args.domain]

    auth = core_client_base.CoreIamAuthenticator(
        args.endpoint, args.core_user, args.core_password
    )
    dns_client = dns_clients.TinyDNSCoreClient(base_url=args.endpoint, auth=auth)

    print(f"Issue a cert for domains: {domains}")

    issue_cert_dns_core(
        domains, args.email, dns_client, private_key_path=args.private_key_path
    )

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
from __future__ import annotations

import logging
import os
import typing as tp

from acme import challenges
from acme import client as acme_lib_client
from acme import crypto_util
from acme import errors
from acme import messages
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose

from gcl_certbot_plugin import clients as dns_clients

LOG = logging.getLogger(__name__)


# This is the staging point for ACME-V2 within Let's Encrypt.
DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
USER_AGENT = "python-acme-example"

# Account key size
ACC_KEY_BITS = 2048

# Certificate private key size
CERT_PKEY_BITS = 2048


def get_or_create_client_private_key(key_path: str) -> rsa.RSAPrivateKey:
    """Get or create a client private key."""
    # Try to get the private key
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    # If it doesn't exist, create it
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    new_client_key = rsa.generate_private_key(
        public_exponent=65537, key_size=ACC_KEY_BITS, backend=default_backend()
    )
    raw_client_key = new_client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Save the private key
    with open(key_path, "wb") as f:
        f.write(raw_client_key)

    return serialization.load_pem_private_key(
        raw_client_key, password=None, backend=default_backend()
    )


def get_acme_client(
    private_client_key: rsa.RSAPrivateKey,
    email: str,
    user_agent: str = USER_AGENT,
    directory_url: str = DIRECTORY_URL,
) -> acme_lib_client.ClientV2:
    """Get ACME client."""
    acc_key = jose.JWKRSA(key=private_client_key)

    net = acme_lib_client.ClientNetwork(acc_key, user_agent=user_agent)
    directory = acme_lib_client.ClientV2.get_directory(directory_url, net)
    client = acme_lib_client.ClientV2(directory, net=net)

    try:
        client.net.account = client.new_account(
            messages.NewRegistration.from_data(
                email=email,
                terms_of_service_agreed=True,
                only_return_existing=True,
            )
        )
    except errors.ConflictError as e:
        account_url = e.location
        LOG.info("Account already exists: %s", account_url)

        client.net.account = messages.RegistrationResource(
            body=messages.Registration(
                terms_of_service_agreed=True, only_return_existing=True
            ),
            uri=account_url,
        )

    return client


def new_csr_comp(
    domains_name: tp.Collection[str], pkey_pem: bytes | None = None
) -> tuple[bytes, bytes]:
    """Create certificate signing request."""
    if pkey_pem is None:
        # Create private key.
        pkey = rsa.generate_private_key(public_exponent=65537, key_size=CERT_PKEY_BITS)
        pkey_pem = pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    csr_pem = crypto_util.make_csr(pkey_pem, list(domains_name))
    return pkey_pem, csr_pem


def select_dns01_chall(
    orderr: messages.OrderResource,
) -> list[challenges.DNS01]:
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = orderr.authorizations
    chs = []

    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.DNS01):
                chs.append(i)

    if len(chs) > 0:
        return chs

    raise RuntimeError("DNS-01 challenge was not offered by the CA server.")


def dns_records_for_challenge(
    domains: tp.Collection[str],
    dns_client: dns_clients.TinyDNSCoreClient,
    validation: str,
) -> list[dict[str, tp.Any]]:
    records = []
    domain_set = set(domains)
    domains_for_challenge = []

    # Don't create wildcard TXT records
    # Example:
    # 1) ["example.com", "*.example.com"] -> ["example.com"]
    # 2) ["*.example.com"] -> ["example.com"]
    for domain in domains:
        if not domain.startswith("*."):
            domains_for_challenge.append(domain)
            continue

        # Add the direct domain for wildcard domain if it doesn't exist
        direct_domain = domain.split(".", 1)[1]
        if direct_domain not in domain_set:
            domains_for_challenge.append(direct_domain)

    # Go to Core DNS and add TXT record
    for domain in domains_for_challenge:
        record = dns_client.create_txt_record(domain, validation, "_acme-challenge")
        records.append(record)

    return records


def perform_dns01(
    domains: tp.Collection[str],
    acme_client: acme_lib_client.ClientV2,
    dns_client: dns_clients.TinyDNSCoreClient,
    challbs: list[challenges.DNS01],
    orderr: messages.OrderResource,
) -> str:
    """Set up standalone webserver and perform DNS-01 challenge."""

    # Go to Core DNS and add TXT records
    records = []

    try:
        for challb in challbs:
            # Get DNS-01 challenge
            response, validation = challb.response_and_validation(acme_client.net.key)

            records += dns_records_for_challenge(domains, dns_client, validation)

            # Let the CA server know that we are ready for the challenge.
            acme_client.answer_challenge(challb, response)

        # Wait for challenge status and then issue a certificate.
        # It is possible to set a deadline time.
        finalized_orderr = acme_client.poll_and_finalize(orderr)

        return finalized_orderr.fullchain_pem
    finally:
        # Clean up TXT records
        for record in records:
            domain_uuid = record["domain"].split("/")[-1]
            record_uuid = record["uuid"]
            dns_client.delete_record(domain_uuid, record_uuid)


def create_cert(
    acme_client: acme_lib_client.ClientV2,
    dns_client: dns_clients.TinyDNSCoreClient,
    domains: tp.Collection[str],
) -> tuple[bytes, bytes, str]:
    """Issue a new certificate."""
    # Create domain private key and CSR
    pkey_pem, csr_pem = new_csr_comp(domains)

    # Issue certificate
    orderr = acme_client.new_order(csr_pem)

    # Select DNS-01 within offered challenges by the CA server
    challbs = select_dns01_chall(orderr)

    # The certificate is ready to be used in the variable "fullchain_pem".
    fullchain_pem = perform_dns01(domains, acme_client, dns_client, challbs, orderr)

    return pkey_pem, csr_pem, fullchain_pem


def renew_cert(
    acme_client: acme_lib_client.ClientV2,
    dns_client: dns_clients.TinyDNSCoreClient,
    domains: tp.Collection[str],
    pkey_pem: bytes,
) -> tuple[bytes, bytes, str]:
    """Renew the certificate with the specified private key."""
    _, csr_pem = new_csr_comp(domains, pkey_pem)
    orderr = acme_client.new_order(csr_pem)
    challbs = select_dns01_chall(orderr)

    # Performing challenge
    fullchain_pem = perform_dns01(domains, acme_client, dns_client, challbs, orderr)

    return pkey_pem, csr_pem, fullchain_pem


def revoke_cert(acme_client: acme_lib_client.ClientV2, fullchain_pem: str) -> None:
    """Revoke the certificate."""
    fullchain_com = x509.load_pem_x509_certificate(fullchain_pem.encode())

    try:
        # revocation reason = 0
        acme_client.revoke(fullchain_com, 0)
    except errors.ConflictError:
        # Certificate already revoked.
        pass

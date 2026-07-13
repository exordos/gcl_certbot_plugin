#    Copyright 2026 Genesis Corporation.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0

import pathlib
import tempfile
import unittest

from certbot.plugins import dns_common
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
import mock

from gcl_certbot_plugin import acme
from gcl_certbot_plugin import clients
from gcl_certbot_plugin import plugin


class DependencyCompatibilityTest(unittest.TestCase):
    def test_certbot_authenticator_interface(self) -> None:
        self.assertTrue(issubclass(plugin.Authenticator, dns_common.DNSAuthenticator))

    def test_cryptography_key_and_csr_roundtrip(self) -> None:
        domain = "dependency-test.example.invalid"

        with tempfile.TemporaryDirectory() as tmp_dir:
            key_path = pathlib.Path(tmp_dir) / "account.pem"
            created_key = acme.get_or_create_client_private_key(str(key_path))
            loaded_key = acme.get_or_create_client_private_key(str(key_path))

        self.assertEqual(
            created_key.public_key(),
            loaded_key.public_key(),
        )

        private_key_pem, csr_pem = acme.new_csr_comp([domain])
        csr = x509.load_pem_x509_csr(csr_pem)
        subject_alt_names = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value

        self.assertIn(domain, subject_alt_names.get_values_for_type(x509.DNSName))
        self.assertTrue(private_key_pem.startswith(b"-----BEGIN PRIVATE KEY-----"))

    @mock.patch("gcl_certbot_plugin.clients.base.CollectionBaseClient")
    def test_sdk_dns_client_create_and_delete(self, collection_client_cls) -> None:
        domains_client = mock.Mock()
        records_client = mock.Mock()
        collection_client_cls.side_effect = [domains_client, records_client]
        domains_client.filter.return_value = [{"uuid": "domain-uuid"}]
        records_client.create.return_value = {
            "uuid": "record-uuid",
            "domain": "/v1/dns/domains/domain-uuid",
        }

        dns_client = clients.TinyDNSCoreClient("https://core.example.invalid")
        record = dns_client.create_txt_record(
            "host.example.invalid",
            "validation-token",
            "_acme-challenge",
        )
        dns_client.delete_record("domain-uuid", record["uuid"])

        domains_client.filter.assert_called_once_with(
            "/v1/dns/domains/", name="example.invalid"
        )
        records_client.create.assert_called_once_with(
            "/v1/dns/domains/domain-uuid/records/",
            {
                "type": "TXT",
                "ttl": 0,
                "record": {
                    "kind": "TXT",
                    "name": "_acme-challenge.host.",
                    "content": "validation-token",
                },
            },
        )
        records_client.delete.assert_called_once_with(
            "/v1/dns/domains/domain-uuid/records/", "record-uuid"
        )

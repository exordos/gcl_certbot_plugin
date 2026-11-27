#    Copyright 2026 Genesis Corporation.
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

from types import SimpleNamespace
from unittest import mock

import dns.resolver
import pytest

from gcl_certbot_plugin import acme


def test_waits_for_exact_token_at_both_resolvers() -> None:
    seen = []
    rounds = {}

    def resolver_factory(**kwargs):
        resolver = mock.Mock()

        def resolve(name, kind):
            key = (name, resolver.nameservers[0])
            seen.append(key)
            rounds[key] = rounds.get(key, 0) + 1
            if rounds[key] == 1:
                return [SimpleNamespace(strings=(b"old-token",))]
            return [SimpleNamespace(strings=(b"new-", b"token"))]

        resolver.resolve.side_effect = resolve
        return resolver

    with (
        mock.patch.object(acme.dns.resolver, "Resolver", side_effect=resolver_factory),
        mock.patch.object(acme.time, "sleep") as sleep,
    ):
        acme.wait_for_dns01(["example.com", "*.example.com"], "new-token")
    assert set(seen) == {
        ("_acme-challenge.example.com", "9.9.9.9"),
        ("_acme-challenge.example.com", "8.8.8.8"),
    }
    assert all(count == 2 for count in rounds.values())
    assert sleep.call_args_list == [mock.call(5), mock.call(10)]


def test_timeout_does_not_accept_nxdomain() -> None:
    with (
        mock.patch.object(acme.dns.resolver, "Resolver") as resolver,
        mock.patch.object(acme.time, "monotonic", side_effect=[0, 0, 0, 181]),
        mock.patch.object(acme.time, "sleep") as sleep,
    ):
        resolver.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
        with pytest.raises(TimeoutError, match="did not propagate"):
            acme.wait_for_dns01(["example.com"], "token")
    sleep.assert_not_called()


@pytest.mark.parametrize("propagated", [True, False])
def test_ca_is_not_notified_before_propagation_and_records_are_cleaned(
    propagated,
) -> None:
    client = mock.Mock()
    dns_client = mock.Mock()
    challenge = mock.Mock()
    challenge.response_and_validation.return_value = ("response", "token")
    record = {"domain": "/domains/zone", "uuid": "record"}
    with (
        mock.patch.object(acme, "dns_records_for_challenge", return_value=[record]),
        mock.patch.object(acme, "wait_for_dns01") as wait,
    ):

        def check(*args):
            client.answer_challenge.assert_not_called()
            if not propagated:
                raise TimeoutError("not visible")

        wait.side_effect = check
        if propagated:
            acme.perform_dns01(
                ["example.com"], client, dns_client, [challenge], "order"
            )
            client.answer_challenge.assert_called_once_with(challenge, "response")
        else:
            with pytest.raises(TimeoutError):
                acme.perform_dns01(
                    ["example.com"], client, dns_client, [challenge], "order"
                )
            client.answer_challenge.assert_not_called()
            client.poll_and_finalize.assert_not_called()
    dns_client.delete_record.assert_called_once_with("zone", "record")

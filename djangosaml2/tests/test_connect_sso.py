"""Tests for the Connect SSO / MFA customisations in djangosaml2.views.

- LoginView stashes the Django session's MFA-done accounts and selected
  account in the cache, keyed by the SAML request id.
- AssertionConsumerServiceView sends ``post_authenticated`` after login and
  restores the stashed MFA/account data into the new session.
"""

from types import SimpleNamespace
from unittest import mock
from urllib.parse import urlparse

from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from djangosaml2 import views
from djangosaml2.signals import post_authenticated
from djangosaml2.tests import conf

User = get_user_model()

SAML_CONFIG = conf.create_conf(
    sp_host="sp.example.com",
    idp_hosts=["idp.example.com"],
    metadata_file="remote_metadata_one_idp.xml",
)


@override_settings(
    SAML_CONFIG=SAML_CONFIG,
    SAML_IGNORE_AUTHENTICATED_USERS_ON_LOGIN=True,
    LOGIN_REDIRECT_URL="/dashboard/",
)
class LoginViewConnectTests(TestCase):
    def _set_session(self, **values):
        session = self.client.session
        session.update(values)
        session.save()

    def _cache_sets(self, mocked_set):
        return {c.args[0]: c.args[1] for c in mocked_set.call_args_list}

    def test_anonymous_login_caches_mfa_and_account(self):
        # Connect stores an Account model here; any session-serialisable value works
        self._set_session(mfa_done_accounts=["Beta"], account="Acme")

        with mock.patch.object(views.cache, "set") as mocked_set:
            response = self.client.get(reverse("saml2_login"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(urlparse(response["Location"]).hostname, "idp.example.com")
        sets = self._cache_sets(mocked_set)
        mfa_keys = [k for k in sets if k.endswith("_mfa_done_accounts")]
        account_keys = [k for k in sets if k.endswith("_current_account")]
        self.assertEqual(len(mfa_keys), 1)
        self.assertEqual(len(account_keys), 1)
        self.assertEqual(sets[mfa_keys[0]], ["Beta"])
        self.assertEqual(sets[account_keys[0]], "Acme")
        # both keys share the same SAML request id prefix
        self.assertEqual(
            mfa_keys[0][: -len("_mfa_done_accounts")],
            account_keys[0][: -len("_current_account")],
        )
        for c in mocked_set.call_args_list:
            self.assertEqual(c.args[2], 15 * 60)

    def test_anonymous_login_without_session_data_caches_nothing(self):
        with mock.patch.object(views.cache, "set") as mocked_set:
            response = self.client.get(reverse("saml2_login"))

        self.assertEqual(response.status_code, 302)
        mocked_set.assert_not_called()

    def test_authenticated_user_without_mfa_is_redirected(self):
        self.client.force_login(User.objects.create(username="user"))

        response = self.client.get(reverse("saml2_login"))

        self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)

    def test_authenticated_user_with_mfa_is_redirected(self):
        # should_prevent_auth() already blocks any authenticated user, so the
        # Connect MFA check does not change the outcome here.
        self.client.force_login(User.objects.create(username="user"))
        self._set_session(mfa_done_accounts=["Acme"])

        with mock.patch.object(views.cache, "set") as mocked_set:
            response = self.client.get(reverse("saml2_login"))

        self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)
        mocked_set.assert_not_called()

    def test_request_without_django_session(self):
        request = RequestFactory().get("/login/")
        request.user = mock.Mock(is_authenticated=False)
        request.saml_session = mock.MagicMock()

        with mock.patch.object(views.cache, "set") as mocked_set:
            response = views.LoginView.as_view()(request)

        self.assertEqual(response.status_code, 302)
        mocked_set.assert_not_called()


class AuthenticateUserConnectTests(TestCase):
    session_id = "id-connect-123"

    def setUp(self):
        cache.clear()
        self.user = User.objects.create(username="sso-user")
        self.request = RequestFactory().post("/acs/")
        SessionMiddleware(lambda r: None).process_request(self.request)
        self.request.session.save()
        self.request.saml_session = mock.MagicMock()
        self.view = views.AssertionConsumerServiceView()
        self.view.request = self.request
        self.received = []
        post_authenticated.connect(self._receiver)
        self.addCleanup(post_authenticated.disconnect, self._receiver)

    def _receiver(self, sender, **kwargs):
        self.received.append((sender, kwargs))

    def _authenticate(self, session_id=None):
        with mock.patch.object(views.auth, "authenticate", return_value=self.user), \
                mock.patch.object(views.auth, "login") as login, \
                mock.patch.object(views, "_set_subject_id"):
            user = self.view.authenticate_user(
                self.request,
                {"name_id": "nameid", "issuer": "https://idp.example.com"},
                {},
                True,
                {},
                session_id,
            )
        login.assert_called_once_with(self.request, self.user)
        return user

    def test_sends_post_authenticated_signal(self):
        user = self._authenticate()

        self.assertEqual(user, self.user)
        self.assertEqual(len(self.received), 1)
        sender, kwargs = self.received[0]
        self.assertIs(sender, self.request)
        self.assertEqual(kwargs["session_info"]["name_id"], "nameid")

    def test_failing_receiver_does_not_break_login(self):
        def boom(sender, **kwargs):
            raise RuntimeError("boom")

        post_authenticated.connect(boom)
        self.addCleanup(post_authenticated.disconnect, boom)

        self.assertEqual(self._authenticate(), self.user)

    def test_without_session_id_leaves_session_untouched(self):
        cache.set(self.session_id + "_mfa_done_accounts", ["Acme"], 60)

        self._authenticate(session_id=None)

        self.assertNotIn("mfa_done_accounts", self.request.session)
        self.assertNotIn("current_account", self.request.session)
        self.assertEqual(cache.get(self.session_id + "_mfa_done_accounts"), ["Acme"])

    def test_restores_cached_mfa_accounts(self):
        cache.set(self.session_id + "_mfa_done_accounts", ["Acme"], 60)

        self._authenticate(self.session_id)

        self.assertEqual(self.request.session["mfa_done_accounts"], ["Acme"])
        self.assertIsNone(cache.get(self.session_id + "_mfa_done_accounts"))

    def test_merges_cached_mfa_accounts_without_duplicates(self):
        self.request.session["mfa_done_accounts"] = ["Acme", "Beta"]
        cache.set(self.session_id + "_mfa_done_accounts", ["Beta", "Gamma"], 60)

        self._authenticate(self.session_id)

        self.assertCountEqual(
            self.request.session["mfa_done_accounts"], ["Acme", "Beta", "Gamma"]
        )

    def test_restores_current_account_and_marks_mfa_done(self):
        cache.set(self.session_id + "_current_account", SimpleNamespace(name="Acme"), 60)

        self._authenticate(self.session_id)

        self.assertEqual(self.request.session["current_account"].name, "Acme")
        self.assertEqual(self.request.session["mfa_done_accounts"], ["Acme"])
        self.assertIsNone(cache.get(self.session_id + "_current_account"))

    def test_current_account_already_in_mfa_list_is_not_duplicated(self):
        cache.set(self.session_id + "_mfa_done_accounts", ["Acme"], 60)
        cache.set(self.session_id + "_current_account", SimpleNamespace(name="Acme"), 60)

        self._authenticate(self.session_id)

        self.assertEqual(self.request.session["mfa_done_accounts"], ["Acme"])

    def test_current_account_added_to_existing_mfa_list(self):
        cache.set(self.session_id + "_mfa_done_accounts", ["Beta"], 60)
        cache.set(self.session_id + "_current_account", SimpleNamespace(name="Acme"), 60)

        self._authenticate(self.session_id)

        self.assertCountEqual(self.request.session["mfa_done_accounts"], ["Acme", "Beta"])

    def test_cached_account_overrides_account_set_by_signal_receiver(self):
        # Connect's post_authenticated receiver picks a default current_account;
        # the account the user selected before SSO (cached) wins.
        def pick_default(sender, **kwargs):
            sender.session["current_account"] = SimpleNamespace(name="Default")

        post_authenticated.connect(pick_default)
        self.addCleanup(post_authenticated.disconnect, pick_default)
        cache.set(self.session_id + "_current_account", SimpleNamespace(name="Acme"), 60)

        self._authenticate(self.session_id)

        self.assertEqual(self.request.session["current_account"].name, "Acme")

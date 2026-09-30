from django.test import SimpleTestCase, override_settings
from django.urls import reverse

import encryption_algorithms.atbash_rot13 as ar
import encryption_algorithms.rsa_algo as ra
import encryption_algorithms.substitution_cipher as sc
import encryption_algorithms.swapping_algo as sa
import encryption_algorithms.vigenere_cipher as vc
from home import vault_crypto
from home.backends import get_backend, reset_backend


class CipherTests(SimpleTestCase):
    def test_caesar_roundtrip_and_non_letters(self):
        text = "Hello, World! 123 é"
        enc = sc.caesar_cipher(text, 3)
        self.assertEqual(enc, "Khoor, Zruog! 123 é")
        self.assertEqual(sc.caesar_decrypt(enc, 3), text)

    def test_swapping_handles_any_characters(self):
        text = "Hello, World 123!"
        self.assertEqual(sa.swapping_encrypt(sa.swapping_encrypt(text)), text)

    def test_atbash_rot13(self):
        self.assertEqual(ar.atbash_cipher("Hello"), "Svool")
        self.assertEqual(ar.rot13(ar.rot13("Hello, é")), "Hello, é")

    def test_vigenere_roundtrip(self):
        self.assertEqual(vc.vigenere_encrypt("ATTACKATDAWN", "LEMON"), "LXFOPVEFRNHR")
        self.assertEqual(vc.vigenere_decrypt("LXFOPVEFRNHR", "LEMON"), "ATTACKATDAWN")

    def test_rsa_roundtrip(self):
        _, (d, n) = ra.rsa_generate_keys()
        enc = ra.rsa_algo("Hi there!")
        self.assertEqual(ra.rsa_decrypt_message(enc, d, n), "Hi there!")

    def test_rsa_rejects_out_of_range_characters(self):
        with self.assertRaises(ValueError):
            ra.rsa_algo("日本語" * 1000 + "\U0001F600")


class ToolViewTests(SimpleTestCase):
    def post(self, **data):
        return self.client.post(reverse('encrypt_data'), data,
                                headers={'X-Requested-With': 'XMLHttpRequest'})

    def test_encrypt_and_decrypt_json(self):
        r = self.post(plain_text='Hello', algorithm='1', key='3', mode='encrypt')
        self.assertEqual(r.json()['result'], 'Khoor')
        r = self.post(plain_text='Khoor', algorithm='1', key='3', mode='decrypt')
        self.assertEqual(r.json()['result'], 'Hello')

    def test_errors(self):
        self.assertEqual(self.post(plain_text='x', algorithm='1', key='abc').status_code, 400)
        self.assertEqual(self.post(plain_text='x', algorithm='4', key='').status_code, 400)
        self.assertEqual(self.post(plain_text='', algorithm='3').status_code, 400)
        self.assertEqual(self.post(plain_text='x', algorithm='0').status_code, 400)

    def test_rsa_decrypt_garbage(self):
        self.assertEqual(self.post(plain_text='not numbers', algorithm='2', mode='decrypt').status_code, 400)

    def test_get_redirects_to_tools(self):
        self.assertRedirects(self.client.get(reverse('encrypt_data')), reverse('tools'),
                             fetch_redirect_response=False)

    def test_public_pages_render(self):
        for name in ('home', 'documentaion', 'examples', 'about', 'symmetric', 'asymmetric', 'tools', 'vault'):
            self.assertEqual(self.client.get(reverse(name)).status_code, 200, name)


def _token(uid, email, name, admin=False):
    return f"{uid}|{email}|{name}" + ("|admin" if admin else "")


@override_settings(CYM_BACKEND='memory')
class VaultTests(SimpleTestCase):
    def setUp(self):
        reset_backend()

    def login(self, uid='u1', email='alice@example.com', name='alice'):
        return self.client.post(reverse('vault_session'),
                                {'id_token': _token(uid, email, name), 'username': name})

    def test_session_exchange_and_dashboard_guard(self):
        self.assertEqual(self.client.get(reverse('vault_dashboard')).status_code, 302)
        r = self.login()
        self.assertEqual(r.json(), {'ok': True, 'next': '/vault/dashboard'})
        self.assertEqual(self.client.get(reverse('vault_dashboard')).status_code, 200)
        self.assertRedirects(self.client.get(reverse('vault')), reverse('vault_dashboard'),
                             fetch_redirect_response=False)

    def test_bad_token_rejected(self):
        r = self.client.post(reverse('vault_session'), {'id_token': 'garbage'})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.client.get(reverse('vault_dashboard')).status_code, 302)

    def test_logout_requires_post_and_clears_session(self):
        self.login()
        self.assertEqual(self.client.get(reverse('vault_logout')).status_code, 405)
        self.client.post(reverse('vault_logout'))
        self.assertEqual(self.client.get(reverse('vault_dashboard')).status_code, 302)

    def test_entries_are_encrypted_and_private(self):
        self.login()
        self.client.post(reverse('vault_create'), {'title': 'Secret', 'content': 'top secret text'})
        backend = get_backend()
        (entry,) = backend.list_entries('u1')
        self.assertNotIn('top secret', entry['content_encrypted'])
        salt = backend.get_profile('u1')['salt']
        self.assertEqual(vault_crypto.decrypt('u1', salt, entry['content_encrypted']), 'top secret text')
        self.assertContains(self.client.get(reverse('vault_dashboard')), 'Secret')

        self.client.post(reverse('vault_logout'))
        self.login('u2', 'eve@example.com', 'eve')
        self.assertEqual(self.client.get(reverse('vault_edit', args=[entry['id']])).status_code, 404)
        self.assertEqual(self.client.post(reverse('vault_delete', args=[entry['id']])).status_code, 404)
        self.assertEqual(len(backend.list_entries('u1')), 1)

    def test_per_user_keys_differ(self):
        b = get_backend()
        s1, s2 = b.get_profile('u1')['salt'], b.get_profile('u2')['salt']
        token = vault_crypto.encrypt('u1', s1, 'hello')
        self.assertEqual(vault_crypto.decrypt('u1', s1, token), 'hello')
        with self.assertRaises(Exception):
            vault_crypto.decrypt('u2', s2, token)

    def test_edit_and_delete(self):
        self.login()
        self.client.post(reverse('vault_create'), {'title': 'A', 'content': 'one'})
        backend = get_backend()
        eid = backend.list_entries('u1')[0]['id']
        self.client.post(reverse('vault_edit', args=[eid]), {'title': 'B', 'content': 'two'})
        e = backend.get_entry('u1', eid)
        salt = backend.get_profile('u1')['salt']
        self.assertEqual((e['title'], vault_crypto.decrypt('u1', salt, e['content_encrypted'])), ('B', 'two'))
        self.client.post(reverse('vault_delete', args=[eid]))
        self.assertEqual(backend.list_entries('u1'), [])

    def test_empty_fields_rejected(self):
        self.login()
        self.client.post(reverse('vault_create'), {'title': '', 'content': 'x'})
        self.client.post(reverse('vault_create'), {'title': 'x', 'content': '  '})
        self.assertEqual(get_backend().list_entries('u1'), [])


@override_settings(CYM_BACKEND='memory')
class AdminPanelTests(SimpleTestCase):
    def setUp(self):
        reset_backend()

    def login(self, uid, email, name, admin=False):
        self.client.post(reverse('vault_session'),
                         {'id_token': _token(uid, email, name, admin), 'username': name})

    def test_non_admin_gets_404(self):
        self.login('u1', 'a@example.com', 'a')
        self.assertEqual(self.client.get(reverse('admin_panel')).status_code, 404)
        self.assertEqual(
            self.client.post(reverse('admin_user_action', args=['u1']), {'action': 'delete'}).status_code, 404)

    def test_anonymous_redirected(self):
        self.assertEqual(self.client.get(reverse('admin_panel')).status_code, 302)

    def test_admin_lists_disables_and_deletes(self):
        self.login('u2', 'bob@example.com', 'bob')
        self.client.post(reverse('vault_create'), {'title': 'T', 'content': 'c'})
        self.client.post(reverse('vault_logout'))
        self.login('adm', 'root@example.com', 'root', admin=True)

        self.assertContains(self.client.get(reverse('admin_panel')), 'bob@example.com')
        self.assertContains(self.client.get(reverse('admin_panel'), {'q': 'nomatch'}), 'No users match')

        self.client.post(reverse('admin_user_action', args=['u2']), {'action': 'disable'})
        self.assertTrue(get_backend().users['u2']['disabled'])
        self.client.post(reverse('admin_user_action', args=['u2']), {'action': 'enable'})
        self.assertFalse(get_backend().users['u2']['disabled'])

        self.client.post(reverse('admin_user_action', args=['u2']), {'action': 'delete'})
        self.assertNotIn('u2', get_backend().users)
        self.assertEqual(get_backend().list_entries('u2'), [])

    def test_admin_cannot_modify_self(self):
        self.login('adm', 'root@example.com', 'root', admin=True)
        self.client.post(reverse('admin_user_action', args=['adm']), {'action': 'delete'})
        self.assertIn('adm', get_backend().users)

    def test_disabled_user_cannot_sign_in(self):
        self.login('u3', 'c@example.com', 'c')
        self.client.post(reverse('vault_logout'))
        get_backend().set_disabled('u3', True)
        r = self.client.post(reverse('vault_session'), {'id_token': _token('u3', 'c@example.com', 'c')})
        self.assertEqual(r.status_code, 401)

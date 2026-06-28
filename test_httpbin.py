#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""responder-httpbin test suite.

Ported from the original Flask test_client-based tests to responder's built-in
httpx test client (Starlette TestClient). The client uses ``base_url`` of
``http://localhost`` so request URLs / Host headers match the original
assertions, and ``follow_redirects=False`` to mirror the Flask test client.
"""
import os
import base64
import unittest
import contextlib
import json
from io import BytesIO
from hashlib import md5, sha256, sha512

from starlette.testclient import TestClient

import httpbin
from httpbin.helpers import parse_multi_value_header, parse_dict_header


@contextlib.contextmanager
def _setenv(key, value):
    """Context manager to set an environment variable temporarily."""
    old_value = os.environ.get(key, None)
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value

    yield

    if old_value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value


def _string_to_base64(string):
    """Encodes string to utf-8 and then base64"""
    utf8_encoded = string.encode('utf-8')
    return base64.urlsafe_b64encode(utf8_encoded)


def _hash(data, algorithm):
    """Encode binary data according to specified algorithm, use MD5 by default"""
    if algorithm == 'SHA-256':
        return sha256(data).hexdigest()
    elif algorithm == 'SHA-512':
        return sha512(data).hexdigest()
    else:
        return md5(data).hexdigest()


def _make_digest_auth_header(username, password, method, uri, nonce,
                             realm=None, opaque=None, algorithm=None,
                             qop=None, cnonce=None, nc=None, body=None):
    """Compile a digest authentication header string."""

    assert username
    assert password
    assert nonce
    assert method
    assert uri
    assert algorithm in ('MD5', 'SHA-256', 'SHA-512', None)

    a1 = ':'.join([username, realm or '', password])
    ha1 = _hash(a1.encode('utf-8'), algorithm)

    a2 = ':'.join([method, uri])
    if qop == 'auth-int':
        a2 = ':'.join([a2, _hash(body or b'', algorithm)])
    ha2 = _hash(a2.encode('utf-8'), algorithm)

    a3 = ':'.join([ha1, nonce])
    if qop in ('auth', 'auth-int'):
        assert cnonce
        assert nc
        a3 = ':'.join([a3, nc, cnonce, qop])

    a3 = ':'.join([a3, ha2])
    auth_response = _hash(a3.encode('utf-8'), algorithm)

    auth_header = \
        'Digest username="{0}", response="{1}", uri="{2}", nonce="{3}"'\
            .format(username, auth_response, uri, nonce)

    # 'realm' and 'opaque' should be returned unchanged, even if empty
    if realm is not None:
        auth_header += ', realm="{0}"'.format(realm)
    if opaque is not None:
        auth_header += ', opaque="{0}"'.format(opaque)

    if algorithm:
        auth_header += ', algorithm="{0}"'.format(algorithm)
    if cnonce:
        auth_header += ', cnonce="{0}"'.format(cnonce)
    if nc:
        auth_header += ', nc={0}'.format(nc)
    if qop:
        auth_header += ', qop={0}'.format(qop)

    return auth_header


class HttpbinTestCase(unittest.TestCase):
    """responder-httpbin tests"""

    def setUp(self):
        self.app = TestClient(
            httpbin.api, base_url="http://localhost", follow_redirects=False
        )

    def get_data(self, response):
        return response.content

    def test_index(self):
        response = self.app.get('/', headers={'User-Agent': 'test'})
        self.assertEqual(response.status_code, 200)

    def test_response_headers_simple(self):
        supported_verbs = ['get', 'post']
        for verb in supported_verbs:
            method = getattr(self.app, verb)
            response = method('/response-headers?animal=dog')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get_list('animal', split_commas=True), ['dog'])
            assert json.loads(response.content.decode('utf-8'))['animal'] == 'dog'

    def test_response_headers_multi(self):
        supported_verbs = ['get', 'post']
        for verb in supported_verbs:
            method = getattr(self.app, verb)
            response = method('/response-headers?animal=dog&animal=cat')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get_list('animal', split_commas=True), ['dog', 'cat'])
            assert json.loads(response.content.decode('utf-8'))['animal'] == ['dog', 'cat']

    def test_get(self):
        response = self.app.get(
            '/get', headers={'User-Agent': 'test', 'Content-Length': '0'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode('utf-8'))
        self.assertEqual(data['args'], {})
        self.assertEqual(data['headers']['Host'], 'localhost')
        self.assertEqual(data['headers']['Content-Length'], '0')
        self.assertEqual(data['headers']['User-Agent'], 'test')
        self.assertEqual(data['url'], 'http://localhost/get')
        self.assertTrue(response.content.endswith(b'\n'))

    def test_anything(self):
        response = self.app.get('/anything')
        self.assertEqual(response.status_code, 200)
        response = self.app.get('/anything/foo/bar', headers={'Content-Length': '0'})
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode('utf-8'))
        self.assertEqual(data['args'], {})
        self.assertEqual(data['headers']['Host'], 'localhost')
        self.assertEqual(data['headers']['Content-Length'], '0')
        self.assertEqual(data['url'], 'http://localhost/anything/foo/bar')
        self.assertEqual(data['method'], 'GET')
        self.assertTrue(response.content.endswith(b'\n'))

    def test_base64(self):
        greeting = u'Здравствуй, мир!'
        b64_encoded = _string_to_base64(greeting)
        response = self.app.get('/base64/' + b64_encoded.decode('utf-8'))
        content = response.content.decode('utf-8')
        self.assertEqual(greeting, content)

    def test_post_binary(self):
        response = self.app.post('/post',
                                 content=b'\x01\x02\x03\x81\x82\x83',
                                 headers={'Content-Type': 'application/octet-stream'})
        self.assertEqual(response.status_code, 200)

    def test_post_body_text(self):
        with open('httpbin/core.py') as f:
            response = self.app.post('/post', data={"file": f.read()})
        self.assertEqual(response.status_code, 200)

    def test_post_body_binary(self):
        response = self.app.post(
            '/post',
            data={"file": '\x01\x02\x03\x81\x82\x83'})
        self.assertEqual(response.status_code, 200)

    def test_post_body_unicode(self):
        response = self.app.post('/post', content=u'оживлённым'.encode('utf-8'))
        self.assertEqual(json.loads(response.content.decode('utf-8'))['data'], u'оживлённым')

    def test_post_file_with_missing_content_type_header(self):
        # Build the multipart body manually so the file part carries no
        # Content-Type header.
        data = '--bound\r\nContent-Disposition: form-data; name="media"; '
        data += 'filename="test.bin"\r\n\r\n\xa5\xc6\n--bound--\r\n'
        response = self.app.post(
            '/post',
            headers={'Content-Type': 'multipart/form-data; boundary=bound'},
            content=data.encode('latin-1'),
        )
        self.assertEqual(response.status_code, 200)

    """
    This is currently a sort of negative-test.
    We validate that Transfer-Encoding: chunked requests are unsupported and
    we return 501 Not Implemented (httpbin's documented behavior).
    """
    def test_post_chunked(self):
        data = '{"animal":"dog"}'
        response = self.app.post(
            '/post',
            headers={'Content-Type': 'application/json',
                     'Transfer-Encoding': 'chunked'},
            content=data.encode('utf-8'),
        )
        self.assertEqual(response.status_code, 501)

    def test_set_cors_headers_after_request(self):
        response = self.app.get('/get')
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), '*'
        )

    def test_set_cors_credentials_headers_after_auth_request(self):
        response = self.app.get('/basic-auth/foo/bar')
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Credentials'), 'true'
        )

    def test_set_cors_headers_after_request_with_request_origin(self):
        response = self.app.get('/get', headers={'Origin': 'origin'})
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), 'origin'
        )

    def test_set_cors_headers_with_options_verb(self):
        response = self.app.request('OPTIONS', '/get')
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), '*'
        )
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Credentials'), 'true'
        )
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Methods'),
            'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        )
        self.assertEqual(
            response.headers.get('Access-Control-Max-Age'), '3600'
        )
        self.assertNotIn(
            'Access-Control-Allow-Headers', response.headers
        )

    def test_set_cors_allow_headers(self):
        response = self.app.request('OPTIONS', '/get', headers={'Access-Control-Request-Headers': 'X-Test-Header'})
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Headers'), 'X-Test-Header'
        )

    def test_headers(self):
        headers = {
            "Accept": "*/*",
            "Host": "localhost:1234",
            "User-Agent": "curl/7.54.0",
            "Via": "bar"
        }
        response = self.app.get('/headers', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue({'Accept', 'Host', 'User-Agent'}.issubset(set(response.json()['headers'].keys())))
        self.assertNotIn('Via', response.json()['headers'])

    def test_headers_show_env(self):
        headers = {
            "Accept": "*/*",
            "Host": "localhost:1234",
            "User-Agent": "curl/7.54.0",
            "Via": "bar"
        }
        response = self.app.get('/headers?show_env=true', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue({'Accept', 'Host', 'User-Agent', 'Via'}.issubset(set(response.json()['headers'].keys())))

    def test_user_agent(self):
        response = self.app.get(
            '/user-agent', headers={'User-Agent': 'test'}
        )
        self.assertIn('test', response.content.decode('utf-8'))
        self.assertEqual(response.status_code, 200)

    def test_gzip(self):
        response = self.app.get('/gzip')
        self.assertEqual(response.status_code, 200)

    def test_brotli(self):
        response = self.app.get('/brotli')
        self.assertEqual(response.status_code, 200)

    def test_bearer_auth(self):
        token = 'abcd1234'
        response = self.app.get(
            '/bearer',
            headers={'Authorization': 'Bearer ' + token}
        )
        self.assertEqual(response.status_code, 200)
        assert json.loads(response.content.decode('utf-8'))['token'] == token

    def test_bearer_auth_with_wrong_authorization_type(self):
        """Sending an non-Bearer Authorization header to /bearer should return a 401"""
        auth_headers = (
            ('Authorization', 'Basic 1234abcd'),
            ('Authorization', ''),
            ('',  ''),
        )
        for header in auth_headers:
            if not header[0]:
                response = self.app.get('/bearer')
            else:
                response = self.app.get('/bearer', headers={header[0]: header[1]})
            self.assertEqual(response.status_code, 401)

    def test_bearer_auth_with_missing_token(self):
        """Sending an 'Authorization: Bearer' header with no token to /bearer should return a 401"""
        response = self.app.get(
            '/bearer',
            headers={'Authorization': 'Bearer'}
        )
        self.assertEqual(response.status_code, 401)

    def test_digest_auth_with_wrong_password(self):
        auth_header = 'Digest username="user",realm="wrong",nonce="wrong",uri="/digest-auth/user/passwd/MD5",response="wrong",opaque="wrong"'
        response = self.app.get(
            '/digest-auth/auth/user/passwd/MD5',
            headers={
                'Authorization': auth_header,
            }
        )
        self.assertTrue('Digest' in response.headers.get('WWW-Authenticate'))
        self.assertEqual(response.status_code, 401)

    def test_digest_auth(self):
        """Test different combinations of digest auth parameters"""
        username = 'user'
        password = 'passwd'
        for qop in None, 'auth', 'auth-int',:
            for algorithm in None, 'MD5', 'SHA-256', 'SHA-512':
                for body in None, b'', b'request payload':
                    for stale_after in (None, 1, 4) if algorithm else (None,):
                        self._test_digest_auth(username, password, qop, algorithm, body, stale_after)

    def test_digest_auth_with_wrong_authorization_type(self):
        """Sending an non-digest Authorization header to /digest-auth should return a 401"""
        auth_headers = (
            ('Authorization', 'Basic 1234abcd'),
            ('Authorization', ''),
            ('',  ''),
        )
        for header in auth_headers:
            if not header[0]:
                response = self.app.get('/digest-auth/auth/myname/mysecret')
            else:
                response = self.app.get('/digest-auth/auth/myname/mysecret', headers={header[0]: header[1]})
            self.assertEqual(response.status_code, 401)

    def _test_digest_auth(self, username, password, qop, algorithm=None, body=None, stale_after=None):
        uri = self._digest_auth_create_uri(username, password, qop, algorithm, stale_after)

        unauthorized_response = self._test_digest_auth_first_challenge(uri)

        header = unauthorized_response.headers.get('WWW-Authenticate')

        authorized_response, nonce = self._test_digest_response_for_auth_request(header, username, password, qop, uri, body)
        self.assertEqual(authorized_response.status_code, 200)

        if None == stale_after:
            return

        # test stale after scenario
        self._digest_auth_stale_after_check(header, username, password, uri, body, qop, stale_after)

    def _test_digest_auth_first_challenge(self, uri):
        unauthorized_response = self.app.get(uri)
        # make sure it returns a 401
        self.assertEqual(unauthorized_response.status_code, 401)
        return unauthorized_response

    def _digest_auth_create_uri(self, username, password, qop, algorithm, stale_after):
        uri = '/digest-auth/{0}/{1}/{2}'.format(qop or 'wrong-qop', username, password)
        if algorithm:
            uri += '/' + algorithm
        if stale_after:
            uri += '/{0}'.format(stale_after)
        return uri

    def _digest_auth_stale_after_check(self, header, username, password, uri, body, qop, stale_after):
        for nc in range(2, stale_after + 1):
            authorized_response, nonce = self._test_digest_response_for_auth_request(header, username, password, qop, uri,
                                                                              body, nc)
            self.assertEqual(authorized_response.status_code, 200)
        stale_response, nonce = self._test_digest_response_for_auth_request(header, username, password, qop, uri,
                                                                     body, stale_after + 1)
        self.assertEqual(stale_response.status_code, 401)
        header = stale_response.headers.get('WWW-Authenticate')
        self.assertIn('stale=TRUE', header)

    def _test_digest_response_for_auth_request(self, header, username, password, qop, uri, body, nc=1, nonce=None):
        auth_type, auth_info = header.split(None, 1)
        self.assertEqual(auth_type, 'Digest')

        d = parse_dict_header(auth_info)

        nonce = nonce or d['nonce']
        realm = d['realm']
        opaque = d['opaque']
        if qop:
            self.assertIn(qop, [x.strip() for x in d['qop'].split(',')], 'Challenge should contains expected qop')
        algorithm = d['algorithm']

        cnonce, nc = (_hash(os.urandom(10), "MD5"), '{:08}'.format(nc)) if qop in ('auth', 'auth-int') else (None, None)

        auth_header = _make_digest_auth_header(
            username, password, 'GET', uri, nonce, realm, opaque, algorithm, qop, cnonce, nc, body)

        # make second request
        return self.app.request(
            'GET',
            uri,
            headers={
                'Authorization': auth_header,
            },
            content=body
        ), nonce

    def test_digest_auth_wrong_pass(self):
        """Test different combinations of digest auth parameters"""
        username = 'user'
        password = 'passwd'
        for qop in None, 'auth', 'auth-int',:
            for algorithm in None, 'MD5', 'SHA-256', 'SHA-512':
                for body in None, b'', b'request payload':
                    self._test_digest_auth_wrong_pass(username, password, qop, algorithm, body, 3)

    def _test_digest_auth_wrong_pass(self, username, password, qop, algorithm=None, body=None, stale_after=None):
        uri = self._digest_auth_create_uri(username, password, qop, algorithm, stale_after)
        unauthorized_response = self._test_digest_auth_first_challenge(uri)

        header = unauthorized_response.headers.get('WWW-Authenticate')

        wrong_pass_response, nonce = self._test_digest_response_for_auth_request(header, username, "wrongPassword", qop, uri, body)
        self.assertEqual(wrong_pass_response.status_code, 401)
        header = wrong_pass_response.headers.get('WWW-Authenticate')
        self.assertNotIn('stale=TRUE', header)

        reused_nonce_response, nonce = self._test_digest_response_for_auth_request(header, username, password, qop, uri,
                                                                              body, nonce=nonce)
        self.assertEqual(reused_nonce_response.status_code, 401)
        header = reused_nonce_response.headers.get('WWW-Authenticate')
        self.assertIn('stale=TRUE', header)

    def test_drip(self):
        response = self.app.get('/drip?numbytes=400&duration=2&delay=1')
        self.assertEqual(int(response.headers.get('Content-Length')), 400)
        self.assertEqual(len(self.get_data(response)), 400)
        self.assertEqual(response.status_code, 200)

    def test_drip_with_invalid_numbytes(self):
        for bad_num in -1, 0:
            uri = '/drip?numbytes={0}&duration=2&delay=1'.format(bad_num)
            response = self.app.get(uri)
            self.assertEqual(response.status_code, 400)

    def test_drip_with_custom_code(self):
        response = self.app.get('/drip?numbytes=400&duration=2&code=500')
        self.assertEqual(int(response.headers.get('Content-Length')), 400)
        self.assertEqual(len(self.get_data(response)), 400)
        self.assertEqual(response.status_code, 500)

    def test_get_bytes(self):
        response = self.app.get('/bytes/1024')
        self.assertEqual(len(self.get_data(response)), 1024)
        self.assertEqual(response.status_code, 200)

    def test_bytes_with_seed(self):
        response = self.app.get('/bytes/10?seed=0')
        # The RNG (Mersenne Twister) is stable across CPython 3.x.
        self.assertEqual(
            response.content, b'\xc5\xd7\x14\x84\xf8\xcf\x9b\xf4\xb7o'
        )

    def test_stream_bytes(self):
        response = self.app.get('/stream-bytes/1024')
        self.assertEqual(len(self.get_data(response)), 1024)
        self.assertEqual(response.status_code, 200)

    def test_stream_bytes_with_seed(self):
        response = self.app.get('/stream-bytes/10?seed=0')
        self.assertEqual(
            response.content, b'\xc5\xd7\x14\x84\xf8\xcf\x9b\xf4\xb7o'
        )

    def test_delete_endpoint_returns_body(self):
        response = self.app.request(
            'DELETE',
            '/delete',
            data={'name': 'kevin'},
        )
        form_data = json.loads(response.content.decode('utf-8'))['form']
        self.assertEqual(form_data, {'name': 'kevin'})

    def test_methods__to_status_endpoint(self):
        methods = [
            'GET',
            'HEAD',
            'POST',
            'PUT',
            'DELETE',
            'PATCH',
            'TRACE',
        ]
        for m in methods:
            response = self.app.request(m, '/status/418')
            self.assertEqual(response.status_code, 418)

    def test_status_endpoint_invalid_code(self):
        response = self.app.get('/status/4!9')
        self.assertEqual(response.status_code, 400)

    def test_status_endpoint_invalid_codes(self):
        response = self.app.get('/status/200,402,foo')
        self.assertEqual(response.status_code, 400)

    def test_xml_endpoint(self):
        response = self.app.get('/xml')
        self.assertEqual(
            response.headers.get('Content-Type'), 'application/xml'
        )

    def test_x_forwarded_proto(self):
        response = self.app.get('/get', headers={
            'X-Forwarded-Proto': 'https'
        })
        assert json.loads(response.content.decode('utf-8'))['url'].startswith('https://')

    def test_redirect_n_higher_than_1(self):
        response = self.app.get('/redirect/5')
        self.assertEqual(
            response.headers.get('Location'), '/relative-redirect/4'
        )

    def test_redirect_to_post(self):
        response = self.app.post('/redirect-to?url=/post&status_code=307',
                                 content=b'\x01\x02\x03\x81\x82\x83',
                                 headers={'Content-Type': 'application/octet-stream'})
        self.assertEqual(response.status_code, 307)
        self.assertEqual(
            response.headers.get('Location'), '/post'
        )

    def test_redirect_absolute_param_n_higher_than_1(self):
        response = self.app.get('/redirect/5?absolute=true')
        self.assertEqual(
            response.headers.get('Location'), 'http://localhost/absolute-redirect/4'
        )

    def test_redirect_n_equals_to_1(self):
        response = self.app.get('/redirect/1')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers.get('Location'), '/get'
        )

    def test_relative_redirect_n_equals_to_1(self):
        response = self.app.get('/relative-redirect/1')
        self.assertEqual(
            response.headers.get('Location'), '/get'
        )

    def test_relative_redirect_n_higher_than_1(self):
        response = self.app.get('/relative-redirect/7')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers.get('Location'), '/relative-redirect/6'
        )

    def test_absolute_redirect_n_higher_than_1(self):
        response = self.app.get('/absolute-redirect/5')
        self.assertEqual(
            response.headers.get('Location'), 'http://localhost/absolute-redirect/4'
        )

    def test_absolute_redirect_n_equals_to_1(self):
        response = self.app.get('/absolute-redirect/1')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers.get('Location'), 'http://localhost/get'
        )

    def test_request_range(self):
        response1 = self.app.get('/range/1234')
        self.assertEqual(response1.status_code, 200)
        self.assertEqual(response1.headers.get('ETag'), 'range1234')
        self.assertEqual(response1.headers.get('Content-range'), 'bytes 0-1233/1234')
        self.assertEqual(response1.headers.get('Accept-ranges'), 'bytes')
        self.assertEqual(len(self.get_data(response1)), 1234)

        response2 = self.app.get('/range/1234')
        self.assertEqual(response2.status_code, 200)
        self.assertEqual(response2.headers.get('ETag'), 'range1234')
        self.assertEqual(self.get_data(response1), self.get_data(response2))

    def test_request_range_with_parameters(self):
        response = self.app.get(
            '/range/100?duration=1.5&chunk_size=5',
            headers={'Range': 'bytes=10-24'}
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range100')
        self.assertEqual(response.headers.get('Content-range'), 'bytes 10-24/100')
        self.assertEqual(response.headers.get('Accept-ranges'), 'bytes')
        self.assertEqual(response.headers.get('Content-Length'), '15')
        self.assertEqual(self.get_data(response), 'klmnopqrstuvwxy'.encode('utf8'))

    def test_request_range_first_15_bytes(self):
        response = self.app.get(
            '/range/1000',
            headers={'Range': 'bytes=0-15'}
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range1000')
        self.assertEqual(self.get_data(response), 'abcdefghijklmnop'.encode('utf8'))
        self.assertEqual(response.headers.get('Content-range'), 'bytes 0-15/1000')

    def test_request_range_open_ended_last_6_bytes(self):
        response = self.app.get(
            '/range/26',
            headers={'Range': 'bytes=20-'}
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range26')
        self.assertEqual(self.get_data(response), 'uvwxyz'.encode('utf8'))
        self.assertEqual(response.headers.get('Content-range'), 'bytes 20-25/26')
        self.assertEqual(response.headers.get('Content-Length'), '6')

    def test_request_range_suffix(self):
        response = self.app.get(
            '/range/26',
            headers={'Range': 'bytes=-5'}
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range26')
        self.assertEqual(self.get_data(response), 'vwxyz'.encode('utf8'))
        self.assertEqual(response.headers.get('Content-range'), 'bytes 21-25/26')
        self.assertEqual(response.headers.get('Content-Length'), '5')

    def test_request_out_of_bounds(self):
        response = self.app.get(
            '/range/26',
            headers={'Range': 'bytes=10-5'}
        )

        self.assertEqual(response.status_code, 416)
        self.assertEqual(response.headers.get('ETag'), 'range26')
        self.assertEqual(len(self.get_data(response)), 0)
        self.assertEqual(response.headers.get('Content-range'), 'bytes */26')
        self.assertEqual(response.headers.get('Content-Length'), '0')

        response = self.app.get(
            '/range/26',
            headers={'Range': 'bytes=32-40'}
        )
        self.assertEqual(response.status_code, 416)

        response = self.app.get(
            '/range/26',
            headers={'Range': 'bytes=0-40'}
        )
        self.assertEqual(response.status_code, 416)

    def test_etag_if_none_match_matches(self):
        response = self.app.get(
            '/etag/abc',
            headers={'If-None-Match': 'abc'}
        )
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_none_match_matches_list(self):
        response = self.app.get(
            '/etag/abc',
            headers={'If-None-Match': '"123", "abc"'}
        )
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_none_match_matches_star(self):
        response = self.app.get(
            '/etag/abc',
            headers={'If-None-Match': '*'}
        )
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_none_match_w_prefix(self):
        response = self.app.get(
            '/etag/c3piozzzz',
            headers={'If-None-Match': 'W/"xyzzy", W/"r2d2xxxx", W/"c3piozzzz"'}
        )
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response.headers.get('ETag'), 'c3piozzzz')

    def test_etag_if_none_match_has_no_match(self):
        response = self.app.get(
            '/etag/abc',
            headers={'If-None-Match': '123'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_match_matches(self):
        response = self.app.get(
            '/etag/abc',
            headers={'If-Match': 'abc'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_match_matches_list(self):
        response = self.app.get(
            '/etag/abc',
            headers={'If-Match': '"123", "abc"'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_match_matches_star(self):
        response = self.app.get(
            '/etag/abc',
            headers={'If-Match': '*'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_match_has_no_match(self):
        response = self.app.get(
            '/etag/abc',
            headers={'If-Match': '123'}
        )
        self.assertEqual(response.status_code, 412)
        self.assertNotIn('ETag', response.headers)

    def test_etag_with_no_headers(self):
        response = self.app.get(
            '/etag/abc'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    # --- responder-port parity regression tests --------------------------------
    # These guard fidelity gaps found while porting Flask httpbin to responder.

    def test_multipart_repeated_fields_and_files_become_lists(self):
        response = self.app.post(
            '/post',
            files=[
                ('f', (None, 'v1')),
                ('f', (None, 'v2')),
                ('g', ('a.txt', b'A', 'text/plain')),
                ('g', ('b.txt', b'B', 'text/plain')),
            ],
        )
        data = json.loads(response.content.decode('utf-8'))
        self.assertEqual(data['form']['f'], ['v1', 'v2'])
        self.assertEqual(data['files']['g'], ['A', 'B'])

    def test_blank_query_param_is_kept(self):
        response = self.app.get('/get?foo=&bar=baz')
        data = json.loads(response.content.decode('utf-8'))
        self.assertEqual(data['args']['foo'], '')
        self.assertEqual(data['args']['bar'], 'baz')

    def test_duplicate_request_headers_are_combined(self):
        response = self.app.get('/headers', headers=[('X-Foo', 'a'), ('X-Foo', 'b')])
        self.assertEqual(response.json()['headers']['X-Foo'], 'a, b')

    def test_malformed_digest_header_returns_401_not_500(self):
        response = self.app.get(
            '/digest-auth/auth/user/passwd',
            headers={'Authorization': 'Digest username="user", nonce="abc", qop=auth'},
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn('Digest', response.headers.get('WWW-Authenticate'))

    def test_cookies_are_plain(self):
        response = self.app.get('/cookies/set/foo/bar')
        set_cookie = response.headers.get('Set-Cookie', '')
        self.assertNotIn('HttpOnly', set_cookie)
        self.assertNotIn('SameSite', set_cookie)

    def test_options_undefined_path_returns_404(self):
        response = self.app.request('OPTIONS', '/this-route-does-not-exist')
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')

    def test_status_non_mapped_code_has_html_content_type(self):
        response = self.app.get('/status/500')
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.headers.get('Content-Type'), 'text/html; charset=utf-8'
        )

    def test_parse_multi_value_header(self):
        self.assertEqual(parse_multi_value_header('xyzzy'), ["xyzzy"])
        self.assertEqual(parse_multi_value_header('"xyzzy"'), ["xyzzy"])
        self.assertEqual(parse_multi_value_header('W/"xyzzy"'), ["xyzzy"])
        self.assertEqual(parse_multi_value_header('"xyzzy", "r2d2xxxx", "c3piozzzz"'), ["xyzzy", "r2d2xxxx", "c3piozzzz"])
        self.assertEqual(parse_multi_value_header('W/"xyzzy", W/"r2d2xxxx", W/"c3piozzzz"'), ["xyzzy", "r2d2xxxx", "c3piozzzz"])
        self.assertEqual(parse_multi_value_header('*'), ["*"])


if __name__ == '__main__':
    unittest.main()

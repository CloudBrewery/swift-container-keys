# Copyright (c) 2014 Cloud-A Computing (clouda.ca)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from containerkeys import middleware

from containerkeys.tests import base


class TestContainerKeyUtils(base.TestCase):
    def test_feelgood(self):
        self.assertTrue(True)

    def test_key_matches_simple(self):
        test_key = 'foo'
        test_set = ['foo', 'bar', 'baz']
        self.assertTrue(middleware.key_matches(test_key, test_set))

    def test_key_no_match(self):
        test_key = 'foonomatch'
        test_set = ['foo', 'bar', 'baz']
        self.assertFalse(middleware.key_matches(test_key, test_set))

    def test_generate_metadata_keynames(self):
        keynames = middleware.generate_valid_metadata_keynames('test', 3)
        self.assertEquals(3, len(keynames))
        self.assertEquals(keynames, ['test', 'test-2', 'test-3'])

    def test_generate_metadata_keynames_more(self):
        keynames = middleware.generate_valid_metadata_keynames('test', 5)
        self.assertEquals(5, len(keynames))
        self.assertEquals(keynames, ['test', 'test-2', 'test-3', 'test-4', 'test-5'])

    def test_extract_full_metadata(self):
        meta = {'Full-Key': 'asdf',
                'Full-Key-2': 'fdsa',
                'Full-Key-3': 'nope nope nope'}
        keys = middleware.get_container_keys_from_metadata(meta, 2)

        self.assertTrue('asdf' in keys.get(middleware.FULL_KEY))
        self.assertTrue('fdsa' in keys.get(middleware.FULL_KEY))
        self.assertFalse('nope nope nope' in keys.get(middleware.FULL_KEY))

    def test_extract_request_with_readkeys(self):
        env = {'HTTP_X_CONTAINER_META_READ_KEY': 'readkey'}

        found_key, found_key_value = middleware.extract_request_keys(env)

        self.assertEquals(middleware.READ_KEY, found_key)
        self.assertEquals('readkey', found_key_value)


    def test_extract_request_with_fullkeys(self):
        env = {'HTTP_X_CONTAINER_META_FULL_KEY': 'fullkey'}
        found_key, found_key_value = middleware.extract_request_keys(env)

        self.assertEquals(middleware.FULL_KEY, found_key)
        self.assertEquals('fullkey', found_key_value)

    def test_extract_request_with_bothkeys(self):
        env = {
            'HTTP_X_CONTAINER_META_FULL_KEY': 'fullkey',
            'HTTP_X_CONTAINER_META_READ_KEY': 'readkey'}
        found_key, found_key_value = middleware.extract_request_keys(env)

        self.assertEquals(middleware.FULL_KEY, found_key)
        self.assertEquals('fullkey', found_key_value)

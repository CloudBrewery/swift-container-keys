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

"""
Container Keys Middleware

Allows for access to containers based on a simple key rather than requiring
a user to supply Keystone credentials, and embed them in their application.

Container keys supports two keys, specifically X-Container-Meta-Full-Key and
X-Container-Meta-Read-Key. Whichever is supplied will be authenticated against.
Read-Key will only accept GET requests, not POST/PUT/DELETE, which would be
supported by Full-Key.

Multiple keys can be set per container, of the following format:
    X-Container-Meta-[Full|Read](-[1-9])?
The maximum number of keys that are checked is configurable, and can be used
to implement multiple valid keys per container, or a key recycling policy.
"""

from collections import defaultdict

from swift.common import utils as swift_utils
from swift.common.swob import HTTPUnauthorized

from swift.proxy.controllers.base import get_container_info

FULL_KEY = 'Full-Key'
READ_KEY = 'Read-Key'

FULL_KEY_HEADER = 'HTTP_X_CONTAINER_META_FULL_KEY'
READ_KEY_HAEDER = 'HTTP_X_CONTAINER_META_READ_KEY'

READ_RESTRICTED_METHODS = ['PUT', 'POST', 'DELETE']

DEFAULT_MAX_KEYS_PER_CONTAINER = 3


def generate_valid_metadata_keynames(key_name, max_keys):
    """
    Generates a set of valid key names stored in a container's metadata to
    include in results

    :param key_name: base key (unprefixed)
    :param max_keys: max number of valid keys
    :returns: list of names of keys that are valid.
    """
    cmp_key = key_name.lower()
    valid_keynames = [
        "%s-%s" % (cmp_key, i + 1) for i in xrange(0, max_keys)]
    return [cmp_key, ] + valid_keynames


def get_container_keys_from_metadata(meta, max_keys):
    """
    Extracts the container keys from metadata.

    :param meta: container metadata
    :param max_keys: max number of valid keys to check on a container
    :returns: dict of keys found (possibly empty if no keys set)
    """
    keys = defaultdict(list)
    full_keys = generate_valid_metadata_keynames(FULL_KEY, max_keys)
    read_keys = generate_valid_metadata_keynames(READ_KEY, max_keys)

    for key, value in meta.iteritems():
        v = swift_utils.get_valid_utf8_str(value)
        cmp_key = key.lower()
        if cmp_key in full_keys:
            keys[FULL_KEY].append(v)
        elif cmp_key in read_keys:
            keys[READ_KEY].append(v)
    return keys


def key_matches(to_match, keys):
    """
    Checks whether the to_match key is in the list of keys. This leverages
    the swift streq_const_time string comparator to guard against timing
    attacks.

    :param to_match: a key to check contains
    :param keys: a list of keys to compare against
    :returns: boolean
    """
    return any(
        [swift_utils.streq_const_time(to_match, key) for key in keys])


class ContainerKeys(object):
    """
    WSGI Middleware to grant access to containers based on pre-defined
    Read / Full access API keys on a per-container basis. See the overview
    for more information.

    :param app: The next WSGI filter or app in the paste.deploy chain.
    :param conf: The configuration dict for the middleware.
    """

    def __init__(self, app, conf, max_keys_per_container=DEFAULT_MAX_KEYS_PER_CONTAINER):

        self.app = app
        self.conf = conf
        self.max_keys_per_container = max_keys_per_container
        self.logger = swift_utils.get_logger(conf, log_route='containerkeys')

    def __call__(self, env, start_response):
        """
        Main hook into the WSGI paste.deploy filter/app pipeline.

        :param env: The WSGI environment dict.
        :param start_response: The WSGI start_response hook.
        :returns: Response as per WSGI.
        """

        # Start by passing through based on the least amount of processing
        # possible to regular auth.
        if env.get('HTTP_X_AUTH_TOKEN', False):
            # user is trying standard auth, continue the request per usual.
            return self.app(env, start_response)

        try_key_type, try_key_value = self._get_request_key_headers(env)

        if not try_key_value or not try_key_type:
            # if no headers were attempted, pass through to keystone
            # empty api key header is a no-op
            return self.app(env, start_response)

        keys = self._get_container_keys(env, start_response)
        if not keys:
            # if no keys are set on a container, pass through to keystone
            return self.app(env, start_response)

        #
        # Begin marking requests as invalid, a user actually want to try now.
        #
        if try_key_type == READ_KEY:
            if not key_matches(try_key_value, keys.get(READ_KEY)):
                # invalid key
                return self._invalid(env, start_response)

            if env['REQUEST_METHOD'] in READ_RESTRICTED_METHODS:
                # read keys cannot do non-read actions
                return self._invalid(env, start_response)

        elif (try_key_type == FULL_KEY
                and not key_matches(try_key_value, keys.get(FULL_KEY))):
            # invalid full key
            return self._invalid(env, start_response)

        #
        # Thundercats are GO. Tell us not to continue authorization down the
        # stream.
        #
        env['swift.authorize_override'] = True

        return self.app(env, start_response)

    def _get_request_key_headers(self, env):
        """
        Returns the key attempting to be used for the request

        :param env: The WSGI environment for the request.
        :returns: key type, key value
        """

        headers = env.keys()

        if FULL_KEY_HEADER in headers:
            return FULL_KEY, env.get(FULL_KEY_HEADER)
        elif READ_KEY_HAEDER in headers:
            return READ_KEY, env.get(READ_KEY_HAEDER)

        return None, None

    def _get_container_keys(self, env, account):
        """
        Returns the X-Container-Meta-[Full|Read]-Key-[N]? header values for the
        container, or an empty dict if none are set.

        :param env: The WSGI environment for the request.
        :param account: Account str.
        :returns: {key_type: key_value}
        """
        container_info = get_container_info(env, self.app, swift_source='CK')
        return get_container_keys_from_metadata(container_info['meta'],
                                                self.max_keys_per_container)

    def _invalid(self, env, start_response):
        """
        Performs the necessary steps to indicate a WSGI 401
        Unauthorized response to the request.

        :param env: The WSGI environment for the request.
        :param start_response: The WSGI start_response hook.
        :returns: 401 response as per WSGI.
        """
        if env['REQUEST_METHOD'] == 'HEAD':
            body = None
        else:
            body = '401 Unauthorized: Auth Key invalid\n'
        return HTTPUnauthorized(body=body)(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns the WSGI filter for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    max_keys_per_container = int(conf.get('max_keys_per_container',
                                          DEFAULT_MAX_KEYS_PER_CONTAINER))

    swift_utils.register_swift_info(
        'containerkeys',
        max_keys_per_container=max_keys_per_container)

    def auth_filter(app):
        return ContainerKeys(
            app, conf,
            max_keys_per_container=max_keys_per_container)

    return auth_filter

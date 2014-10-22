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
"""


from swift.common import utils as swift_utils
from swift.common.swob import HTTPUnauthorized

from swift.proxy.controllers.base import get_container_info

FULL_KEY = 'Full-Key'
READ_KEY = 'Read-Key'

FULL_KEY_HEADER = 'HTTP_X_CONTAINER_META_FULL_KEY'
READ_KEY_HAEDER = 'HTTP_X_CONTAINER_META_READ_KEY'

READ_RESTRICTED_METHODS = ['PUT', 'POST', 'DELETE']


def get_container_keys_from_metadata(meta):
    """
    Extracts the container keys from metadata.

    :param meta: account metadata
    :returns: dict of keys found (possibly empty if no keys set)
    """
    keys = {}
    for key, value in meta.iteritems():
        v = swift_utils.get_valid_utf8_str(value)
        if key.lower() == FULL_KEY.lower():
            keys[FULL_KEY] = v
        elif key.lower() == READ_KEY.lower():
            keys[READ_KEY] = v
    return keys


class ContainerKeys(object):
    """
    WSGI Middleware to grant access to containers based on pre-defined
    Read / Full access API keys on a per-container basis. See the overview
    for more information.

    :param app: The next WSGI filter or app in the paste.deploy chain.
    :param conf: The configuration dict for the middleware.
    """

    def __init__(self, app, conf):

        self.app = app
        self.conf = conf
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
            if keys.get(READ_KEY) != try_key_value:
                # invalid key
                return self._invalid(env, start_response)

            if env['REQUEST_METHOD'] in READ_RESTRICTED_METHODS:
                # read keys cannot do non-read actions
                return self._invalid(env, start_response)

        elif try_key_type == FULL_KEY and keys.get(FULL_KEY) != try_key_value:
            # invalid full key
            return self._invalid(env, start_response)

        #
        # Thundercats are GO. Tell us not to continue authorization down the
        # stream.
        #
        def _noop_authorize(req):
            return None
        env['swift.authorize'] = _noop_authorize
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
        Returns the X-Container-Meta-[Full|Read]-Key header values for the
        container, or an empty dict if none are set.

        :param env: The WSGI environment for the request.
        :param account: Account str.
        :returns: {key_type: key_value}
        """
        container_info = get_container_info(env, self.app, swift_source='CK')
        return get_container_keys_from_metadata(container_info['meta'])

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

    swift_utils.register_swift_info('containerkeys')

    def auth_filter(app):
        return ContainerKeys(app, conf)

    return auth_filter

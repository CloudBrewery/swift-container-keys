# Copyright (c) 2014 Cloud-A Computing (clouda.ca)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, find_packages
from containerkeys import __version__ as version

name = 'containerkeys'

setup(
    name=name,
    version=version,
    description='Allows for access to swift containers based on container '
                'metadata values',
    license='Apache License (2.0)',
    classifiers=['Programming Language :: Python'],
    keywords='container api auth authentication openstack',
    author='Cloud-A Computing',
    author_email='adam@clouda.ca',
    packages=find_packages(),
    entry_points={
        'paste.filter_factory': [
            'containerkeys=containerkeys.middleware:filter_factory',
        ],
    },
)

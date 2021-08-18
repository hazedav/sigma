# Output backends for sigmac
# Copyright 2021 Lacework, Inc.
# Author: 

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin


class SplunkBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Lacework Policy Platform."""
    identifier = "lacework"
    active = True
    # our approach to config will be such that we support both an
    # embedded or specified config.
    config_required = False

    def generate(self, sigmaparser):
        """
        Method is called for each sigma rule and receives the parsed rule (SigmaParser)
        """

        # TODO: get config if specified

        # TODO: get backend options

        # TODO: get output options

        # TODO: determine if we're generating query/policy/both
        result = self.generate_query(sigmaparser)

        # TODO: figure out how sigmac writes to files vs. stdout
        return result

    def generate_query(self, sigmaparser):
        # TODO: use yaml
        return (
            '---\n'
            'evaluatorId:\n'
            'queryId:\n'
            'queryText:\n'
        )

    def generate_policy(self, sigmaparser):
        # TODO: use yaml
        return (
            '---\n'
            'policies:\n'
            '  - evaluatorId:\n'
            '    policyId:\n'
            '    title:\n'
            '    enabled:\n'
            '    policyType:\n'
            '    alertEnabled:\n'
            '    alertProfile:\n'
            '    evalFrequency:\n'
            '    queryId:\n'
            '    limit:\n'
            '    severity:\n'
            '    description:\n'
            '    remediation:\n'
        )

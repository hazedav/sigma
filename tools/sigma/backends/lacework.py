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

        result += self.generate_policy(sigmaparser)

        # TODO: figure out how sigmac writes to files vs. stdout
        return result

    def generate_query(self, sigmaparser):
        # TODO: use yaml
        query_id = sigmaparser.parsedyaml.get("title").replace(" ", "_")
        service = sigmaparser.parsedyaml['logsource']['service']
        evaluator_id = ''
        data_source = ''
        if service == 'cloudtrail':
            evaluator_id = 'Cloudtrail'
            data_source = 'CloudTrailRawEvents'
        detection = sigmaparser.parsedyaml.get("detection")
        event_source = ''
        event_name = ''
        filter_content = ''
        if detection.get("selection_source") or detection.get("selection"):
            selection_source = detection.get("selection_source") or detection.get("selection")
            event_source = 'EVENT_SOURCE = ' + selection_source.get("eventSource") + '\n'
            filter_content = event_source
            event_name = selection_source.get("eventName")
            if type(event_name) == list:
                event_name = ', '.join(f'"{name}"' for name in selection_source.get("eventName"))
            else:
                event_name = '"' + event_name + '"'
            filter_content += '        and EVENT_NAME in (' + event_name + ')\n'
            if selection_source.get("requestParameters.attribute"):
                filter_content += '        and EVENT:requestParameters.attribute = "' + selection_source['requestParameters.attribute'] + '"'
            if selection_source.get("requestParameters.userData"):
                filter_content += '        and EVENT:requestParameters.userData = "' + selection_source['requestParameters.userData'] + '"'
        source = 'source {\n        ' + data_source + '\n    }\n    '
        filter = 'filter {\n        ' + filter_content + '\n    }\n'
        columns = '    return distinct {\n        INSERT_ID,\n        INSERT_TIME,\n        EVENT_TIME,\n        EVENT\n    }'
        return (
            '---\n'
            'evaluatorId: ' + evaluator_id + '\n' +
            'queryId: ' + query_id + '\n'
            'queryText:\n' + query_id + ' {\n    ' + source + filter + columns + '\n}\n'
        )

    def generate_policy(self, sigmaparser):
        # TODO: use yaml
        title = sigmaparser.parsedyaml.get("title")
        query_id = sigmaparser.parsedyaml.get("title").replace(" ", "_")
        severity = sigmaparser.parsedyaml.get("level")
        description = sigmaparser.parsedyaml.get("description")
        return (
            '---\n'
            'policies:\n'
            '  - evaluatorId:\n'
            '    policyId:\n'
            '    title: ' + title + '\n'
            '    enabled:\n'
            '    policyType:\n'
            '    alertEnabled:\n'
            '    alertProfile:\n'
            '    evalFrequency:\n'
            '    queryId: ' + query_id + '\n'
            '    limit: 1000\n'
            '    severity: ' + severity + '\n'
            '    description: ' + description + '\n'
            '    remediation:\n'
        )

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

import textwrap
import yaml

from sigma.backends.base import SingleTextQueryBackend
from sigma.backends.exceptions import BackendError


LACEWORK_CONFIG = yaml.load(
    # TODO: build this out to support all the default aws sigma rules
    textwrap.dedent('''
    ---
    services:
      cloudtrail:
        evaluatorId: Cloudtrail
        source: CloudTrailRawEvents
        filterMap:
          eventName: EVENT_NAME
          eventSource: EVENT_SOURCE
          requestParameters: EVENT:requestParameters
        returns:
          - INSERT_ID
          - INSERT_TIME
          - EVENT_TIME
          - EVENT
    '''),
    Loader=yaml.SafeLoader
)


def safe_get(obj, name, inst):
    """
    Sweet helper for getting objects
    """
    try:
        assert isinstance(obj[name], inst)
        value = obj[name]
    except Exception:
        value = inst()

    return value


# YAML Tools
def str_presenter(dumper, data):
    if len(data.splitlines()) > 1:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


yaml.add_representer(str, str_presenter)


class LaceworkBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Lacework Policy Platform."""
    identifier = "lacework"
    active = True
    # our approach to config will be such that we support both an
    # embedded or specified config.
    config_required = False

    andToken = ' AND '
    orToken = ' OR '
    notToken = 'NOT '
    subExpression = '(%s)'
    listExpression = 'in (%s)'
    listSeparator = ', '
    valueExpression = "'%s'"
    nullExpression = '%s is null'
    notNullExpression = '%s is not null'
    mapExpression = '%s = %s'
    mapListsSpecialHandling = True
    mapListValueExpression = '%s %s'

    def generate(self, sigmaparser):
        """
        Method is called for each sigma rule and receives the parsed rule (SigmaParser)
        """
        # TODO: get config if specified

        # via backend options...
        # determine if we're generating query/policy/both
        result = ''
        if LaceworkQuery.should_generate_query(self.backend_options):
            query = LaceworkQuery(LACEWORK_CONFIG, sigmaparser, self)
            result += str(query)
        if LaceworkPolicy.should_generate_policy(self.backend_options):
            result += LaceworkPolicy.generate_policy(sigmaparser)

        return result


class LaceworkQuery:
    def __init__(self, config, sigmaparser, backend):
        # 1. Get Config
        self.config = safe_get(config, 'services', dict)

        # 2. Get Rule
        self.rule = sigmaparser.parsedyaml

        # 3. Get Conditions
        self.conditions = sigmaparser.condparsed

        # 4. Get Service
        logsource = safe_get(self.rule, 'logsource', dict)
        self.service = logsource.get('service') or 'unknown'

        # 5. Validate Rule
        # 5a. Get evaluator_id
        # 5b. Get lql_source
        self.evaluator_id, self.lql_source, self.returns = self.validate()

        # 6. Get Query ID
        self.title, self.query_id = self.get_query_id()

        # 7. Get Filter Maps
        service_config = safe_get(self.config, self.service, dict)
        self.filter_map = safe_get(service_config, 'filterMap', dict)

        # 8. Get Query Text
        self.query_text = self.get_query_text(backend)

    def validate(self):
        # 1. validate logsource service
        if self.service not in self.config:
            raise BackendError(
                f'Service {self.service} is not supported by the Lacework backend')

        # 2. get service config
        service_config = safe_get(self.config, self.service, dict)

        # 3. validate service has an evaluatorId mapping
        evaluatorId = safe_get(service_config, 'evaluatorId', str)

        if not evaluatorId:
            raise BackendError(
                f'Lacework backend could not determine evaluatorId for service {self.service}')

        # 4. validate service has a source mapping
        source = safe_get(service_config, 'source', str)

        if not source:
            raise BackendError(
                f'Lacework backend could not determine source for service {self.service}')

        # 5. validate service has returns
        returns = safe_get(service_config, 'returns', list)

        if not returns:
            raise BackendError(
                f'Lacework backend could not determine returns for service {self.service}')

        return evaluatorId, source, returns

    def get_query_id(self):
        try:
            assert isinstance(self.rule['title'], str)
            title = self.rule['title']
        except Exception:
            title = 'Unknown'

        # TODO: might need to replace additional non-word characters
        query_id = f'Sigma_{title}'.replace(" ", "_").replace("/", "_Or_")

        return title, query_id

    def get_query_text(self, backend):
        query_template = (
            '{id} {{\n'
            '    {source_block}\n'
            '    {filter}\n'
            '    {return_block}\n'
            '}}'
        )

        # 1. get_query_source_block
        source_block = self.get_query_source_block()

        # 2. get_query_filters
        filter_block = self.get_query_filter_block(backend)

        # 3. get_query_returns
        return_block = self.get_query_return_block()

        return query_template.format(
            id=self.query_id,
            source_block=source_block,
            filter=filter_block,
            return_block=return_block
        )

    def get_query_source_block(self):
        source_block_template = (
            'source {{\n'
            '        {source}\n'
            '    }}'
        )
        return source_block_template.format(
            source=self.lql_source
        )

    def get_query_filter_block(self, backend):
        filter_block_template = (
            'filter {{\n'
            '        {filter}\n'
            '    }}'
        )

        for parsed in self.conditions:
            query = backend.generateQuery(parsed)
            before = backend.generateBefore(parsed)
            after = backend.generateAfter(parsed)

            filter = ""
            if before is not None:
                filter = before
            if query is not None:
                filter += self.apply_overrides(self.filter_map, query)
            if after is not None:
                filter += after

            return filter_block_template.format(filter=filter)

    def get_query_return_block(self):
        return_block_template = (
            'return distinct {{\n'
            '{returns}\n'
            '    }}'
        )
        return return_block_template.format(
            returns=',\n'.join(f'        {r}' for r in self.returns)
        )

    def __iter__(self):
        for key, attr in {
            'evaluatorId': 'evaluator_id',
            'queryId': 'query_id',
            'queryText': 'query_text'
        }.items():
            yield (key, getattr(self, attr))

    def __str__(self):
        return yaml.dump(
            dict(self),
            explicit_start=True,
            default_flow_style=False
        )

    @staticmethod
    def apply_overrides(filter_map, query):
        for token, replacement in filter_map.items():
            query = query.replace(token, replacement)
        return query

    @staticmethod
    def should_generate_query(backend_options):
        # if we are explictly requesting a query
        if (
            'query' in backend_options
            and backend_options['query'] is True
        ):
            return True
        # if we are explicitly requesting a policy
        if (
            'policy' in backend_options
            and backend_options['policy'] is True
        ):
            return False
        # we're not being explicit about anything
        return True


class LaceworkPolicy:
    # TOOD: build this out like we did for LaceworkQuery
    @staticmethod
    def should_generate_policy(backend_options):
        # if we are explictly requesting a query
        if (
            'policy' in backend_options
            and backend_options['policy'] is True
        ):
            return True
        # if we are explicitly requesting a policy
        if (
            'query' in backend_options
            and backend_options['query'] is True
        ):
            return False
        # we're not being explicit about anything
        return True

    @staticmethod
    def generate_policy(sigmaparser):
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

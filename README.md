
This module provides functionality to interact with a Wazuh server, including retrieving findings and updating agents.

#### Get Findings
- **Base URL**: Base URL of the Opensearch.
- **Username**: Username for authenticating with the opensearch.
- **Password**: Password for authenticating with the opensearch.

#### Get Agents
- **Base URL**: Base URL of the Wazuh server.
- **Username**: Username for authenticating with the Wazuh server.
- **Password**: Password for authenticating with the Wazuh server.

#### Update Agents
- **Base URL**: Base URL of the Wazuh server.
- **Username**: Username for authenticating with the Wazuh server.
- **Password**: Password for authenticating with the Wazuh server.
- **Agents List**: List of agent IDs (separated by comma), use the keyword 'all' to select all agents.
- **Upgrade Version**: Specify the Wazuh version to upgrade to.
- **Force Upgrade**: Force upgrade.
- **Pretty**: Show results in human-readable format.
- **Wait For Complete**: Disable timeout response.
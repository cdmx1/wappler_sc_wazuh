const axios = require('axios');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
exports.getWazuhFindings = async function (options) {
    try {
        const base_url = this.parse(options.base_url) || "https://localhost:55000";
        const username = this.parse(options.username) || "wazuh";
        const password = this.parse(options.password) || "wazuh";
        const group = this.parse(options.group) || "Servers";

        const authenticate = async () => {
            try {
                const response = await axios.get(`${base_url}/security/user/authenticate?raw=true`, {
                    auth: {
                        username: username,
                        password: password
                    }
                });
                if (response.status === 200) {
                    return `Bearer ${response.data}`;
                } else {
                    throw new Error(`Failed to authenticate. Status code: ${response.status}, Detail: ${response.data}`);
                }
            } catch (error) {
                throw new Error(`Failed to authenticate: ${error}`);
            }
        };

        const getAgents = async () => {
            try {
                const authToken = await authenticate();
                const response = await axios.get(`${base_url}/agents`, {
                    headers: { Authorization: authToken },
                    params: { limit: 100000 }
                });
                return response.data.data.affected_items;
            } catch (error) {
                console.error(`Failed to retrieve agents. Error: ${error}`);
                return [];
            }
        };

        const getAgentsInGroup = async () => {
            if (!group) {
                return await getAgents();
            }
            try {
                const authToken = await authenticate();
                const response = await axios.get(`${base_url}/groups/${group}/agents`, {
                    headers: { Authorization: authToken },
                    params: { limit: 100000 }
                });
                return response.data.data.affected_items;
            } catch (error) {
                console.error(`Failed to retrieve agents for group ${group}. Error: ${error}`);
                return [];
            }
        };

        const getVulnerabilitiesForAgent = async (agent_id, authToken) => {
            try {
                const response = await axios.get(`${base_url}/vulnerability/${agent_id}`, {
                    headers: { Authorization: authToken },
                    params: { limit: 100000 }
                });
                return response.data;
            } catch (error) {
                if (error.response.status === 400) {
                    return null;
                } else {
                    console.error(`Failed to retrieve vulnerabilities for agent ${agent_id}. Error: ${error}`);
                    return null;
                }
            }
        };

        const vulnerabilities_list = { data: { affected_items: [] } };
        const group_agents = await getAgentsInGroup();

        const common_ids = group_agents.map(agent => agent.id);

        let vulncount = 0;

        for (const agent_id of common_ids) {
            const authToken = await authenticate();
            const vulnerabilities = await getVulnerabilitiesForAgent(agent_id, authToken);
            if (vulnerabilities) {
                const filtered_vulnerabilities = vulnerabilities.data.affected_items.filter(vulnerability => vulnerability.condition !== "Package unfixed").map(vulnerability => {
                    vulnerability.agent_ip = group_agents.find(agent => agent.id === agent_id).ip;
                    vulnerability.agent_name = group_agents.find(agent => agent.id === agent_id).name;
                    return vulnerability;
                });
                vulnerabilities_list.data.affected_items.push(...filtered_vulnerabilities);
                vulncount += filtered_vulnerabilities.length;
            }
        }

        vulnerabilities_list.data.total_affected_items = vulncount;

        return vulnerabilities_list;
    } catch (error) {
        console.error(`Error occurred while getting findings: ${error}`);
        return { error: error.message };
    }
};

// Exporting the getAgents function
exports.getAgents = async function (options) {
    try {
        const base_url = this.parse(options.base_url) || "https://localhost:55000";
        const username = this.parse(options.username) || "wazuh";
        const password = this.parse(options.password) || "wazuh";

        const authenticate = async () => {
            try {
                const response = await axios.get(`${base_url}/security/user/authenticate?raw=true`, {
                    auth: {
                        username: username,
                        password: password
                    }
                });
                if (response.status === 200) {
                    return `Bearer ${response.data}`;
                } else {
                    throw new Error(`Failed to authenticate. Status code: ${response.status}, Detail: ${response.data}`);
                }
            } catch (error) {
                throw new Error(`Failed to authenticate: ${error}`);
            }
        };

        const authToken = await authenticate();
        const response = await axios.get(`${base_url}/agents`, {
            headers: { Authorization: authToken },
            params: { limit: 100000 }
        });
        return response.data.data.affected_items;
    } catch (error) {
        console.error(`Failed to retrieve agents. Error: ${error}`);
        return [];
    }
};

exports.upgradeAgents = async function (options) {
    try {
        const base_url = this.parse(options.base_url) || "https://localhost:55000";
        const username = this.parse(options.username) || "wazuh";
        const password = this.parse(options.password) || "wazuh";
        
        const authenticate = async () => {
            try {
                const response = await axios.get(`${base_url}/security/user/authenticate?raw=true`, {
                    auth: {
                        username: username,
                        password: password
                    }
                });
                if (response.status === 200) {
                    return `Bearer ${response.data}`;
                } else {
                    throw new Error(`Failed to authenticate. Status code: ${response.status}, Detail: ${response.data}`);
                }
            } catch (error) {
                throw new Error(`Failed to authenticate: ${error}`);
            }
        };

        const upgradeAgentsEndpoint = `${base_url}/agents/upgrade`;

        const authToken = await authenticate();
        const response = await axios.put(upgradeAgentsEndpoint, {}, {
            headers: { 
                Authorization: authToken,
                'Content-Type': 'application/json'
            },
            params: {
                pretty: options.pretty || false,
                wait_for_complete: options.wait_for_complete || false,
                agents_list: options.agents_list || "all",
                upgrade_version: options.upgrade_version,
                use_http: options.use_http || false,
                force: options.force || false,
                group: options.group
            }
        });

        return response.data;
    } catch (error) {
        console.error(`Error occurred while upgrading agents: ${error}`);
        return { error: error.message };
    }
};
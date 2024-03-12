const axios = require('axios');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const { Client } = require('@opensearch-project/opensearch'); 
exports.getWazuhFindings = async function (options) {
    const base_url = this.parse(options.base_url);
    const username = this.parse(options.username);
    const password = this.parse(options.password);
    const today = new Date();
    const sevenDaysAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000); // 7 days ago in milliseconds
    
    const from_date = `${sevenDaysAgo.getFullYear()}-${(sevenDaysAgo.getMonth() + 1).toString().padStart(2, '0')}-${sevenDaysAgo.getDate().toString().padStart(2, '0')}`;
    const to_date = `${today.getFullYear()}-${(today.getMonth() + 1).toString().padStart(2, '0')}-${today.getDate().toString().padStart(2, '0')}`;
    const opensearchConfig = {
        node: base_url,
        auth: {
            username: username,
            password: password,
        },
        ssl: {
            rejectUnauthorized: false,
        },
        headers: {
            'Content-Type': 'application/json',
        },
    };
    const opensearchClient = new Client(opensearchConfig);
    const indexName = this.parse('wazuh-alerts-*');

    const body = {
        query: {
            bool: {
            must: [
                {
                    match_phrase: {
                        "rule.groups" : "vulnerability-detector"
                    }
                },
                {
                    "range": {
                      "@timestamp": {
                        "gte": from_date,
                        "lte": to_date
                      }
                    }
                }
            ]
            }
        }
            
    };
    try {
        const initialResponse = await opensearchClient.search({
            index: indexName,
            _source : [
                "agent.name",
                "agent.ip",
                "data.vulnerability.cve",
                "data.vulnerability.cvss.cvss3.base_score",
                "data.vulnerability.severity",
                "data.vulnerability.title",
                "data.vulnerability.status",
                "timestamp"
            ],
            scroll: '1m', // Set the scroll time
            size: 1000, // Set an initial batch size
            body: body,
        });
        let hits = initialResponse.body.hits.hits.map(hit => hit._source);
        let scrollId = initialResponse.body._scroll_id;
        
        while (hits.length < initialResponse.body.hits.total.value) {
            const scrollResponse = await opensearchClient.scroll({
            scrollId: scrollId,
            scroll: '1m',
            });
        
            hits = hits.concat(scrollResponse.body.hits.hits.map(hit => hit._source));
            scrollId = scrollResponse.body._scroll_id;
        }
        
        await opensearchClient.clearScroll({
            body: {
            scroll_id: scrollId,
            },
        });
      ///  return hits[0].data.vulnerability.cvss.cvss3.base_score
        let formattedObject = hits.map(item => {
            const cvss3BaseScore = item.data.vulnerability.cvss?.cvss3?.base_score || 'N/A';
            return {
                "agent_ip": item.agent.ip,
                "agent_name": item.agent.name,
                "severity": item.data.vulnerability.severity,
                "cve": item.data.vulnerability.cve,
                "title": item.data.vulnerability.title,
                "cvss3_score": cvss3BaseScore,
                "status": item.data.vulnerability.status,
                "timestamp": item.timestamp
            };
        });
        return formattedObject;
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
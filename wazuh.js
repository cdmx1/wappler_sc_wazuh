const axios = require('axios');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const { Client } = require('@opensearch-project/opensearch'); 
exports.getWazuhFindings = async function (options) {
    const base_url = this.parse(options.base_url);
    const username = this.parse(options.username);
    const password = this.parse(options.password);
    let to_date = new Date().toISOString().split('T')[0];
    let from_date = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    
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
        "query": {
            "bool": {
                "must": [
                    {
                        "match_phrase": {
                            "rule.groups": "vulnerability-detector"
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
        },
        "aggregations": {
            "agent": {
                "terms": {
                    "field": "agent.name",
                    "order": {
                        "_count": "desc"
                    },
                    "size": 1000
                },
                "aggs": {
                    "package": {
                        "terms": {
                            "field": "data.vulnerability.package.name",
                            "order": {
                                "_count": "desc"
                            },
                            "size": 10000
                        },
                        "aggs": {
                            "version": {
                                "terms": {
                                    "field": "data.vulnerability.package.version",
                                    "order": {
                                        "_count": "desc"
                                    },
                                    "size": 10000
                                },
                                "aggs": {
                                    "cve": {
                                        "terms": {
                                            "field": "data.vulnerability.cve",
                                            "order": {
                                                "_count": "desc"
                                            },
                                            "size": 10000
                                        },
                                        "aggs": {
                                            "hits": {
                                                "top_hits": {
                                                    "_source": {
                                                        "includes": [
                                                            "agent.name",
                                                            "agent.ip",
                                                            "data.vulnerability.cve",
                                                            "data.vulnerability.cvss.cvss3.base_score",
                                                            "data.vulnerability.severity",
                                                            "data.vulnerability.title",
                                                            "data.vulnerability.status",
                                                            "@timestamp"
                                                        ]
                                                    },
                                                    "size": 1
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "size": 0
    };
    try {
        const initialResponse = await opensearchClient.search({
            index: indexName,
            scroll: '1m', // Set the scroll time
            size: 1, // Set size to 0 to only retrieve aggregations
            body: body,
        });
    
        let aggregations = initialResponse.body.aggregations;
        let scrollId = initialResponse.body._scroll_id;
    
        while (true) {
            const scrollResponse = await opensearchClient.scroll({
                scrollId: scrollId,
                scroll: '1m',
            });
    
            if (scrollResponse.body.aggregations) {
                // If there are aggregations in the scroll response, merge them with existing aggregations
                aggregations = mergeAggregations(aggregations, scrollResponse.body.aggregations);
            }
    
            if (!scrollResponse.body.hits || scrollResponse.body.hits.hits.length === 0) {
                // Break the loop if there are no more hits to scroll
                break;
            }
    
            scrollId = scrollResponse.body._scroll_id;
        }
    
        await opensearchClient.clearScroll({
            body: {
                scroll_id: scrollId,
            },
        });
       
        let sourceData = [];
        aggregations.agent.buckets.forEach(agentBucket => {
            agentBucket.package.buckets.forEach(packageBucket => {
                packageBucket.version.buckets.forEach(versionBucket => {
                    versionBucket.cve.buckets.forEach(cveBucket => {
                        cveBucket.hits.hits.hits.forEach(hit => {
                            sourceData.push(hit._source);
                        });
                    });
                });
            });
        });

        let formattedObject = sourceData.map(item => {
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
        
        return {
            data: {
                affected_items: formattedObject,
                total_affected_items: formattedObject.length
            }
        };
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
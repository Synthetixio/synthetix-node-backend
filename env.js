const {
  PORT = '3005',
  UPSTREAM_IPFS_URL = 'http://127.0.0.1:5001',
  UPSTREAM_IPFS_CLUSTER_URL = 'http://127.0.0.1:9095',
  IPFS_GATEWAY_URL = 'http://127.0.0.1:8080',
} = process.env;

const GRAPH_API_ENDPOINT =
  'https://api.studio.thegraph.com/query/71164/vd-practice-v1/version/latest';

module.exports = {
  PORT,
  UPSTREAM_IPFS_URL,
  UPSTREAM_IPFS_CLUSTER_URL,
  IPFS_GATEWAY_URL,
  GRAPH_API_ENDPOINT,
};

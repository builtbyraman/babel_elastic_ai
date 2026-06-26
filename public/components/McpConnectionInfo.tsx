import React, { useState } from 'react';
import {
  EuiBadge,
  EuiButtonIcon,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';

const MCP_JSON_TEMPLATE = `{
  "mcpServers": {
    "sigma-ai": {
      "command": "/path/to/babel/server/mcp/.venv/bin/python",
      "args": ["/path/to/babel/server/mcp/server.py"],
      "env": {
        "SIGMA_API_URL": "http://localhost:8001",
        "KIBANA_URL": "http://localhost:5601",
        "KIBANA_USERNAME": "elastic",
        "KIBANA_PASSWORD": "<your-kibana-password>",
        "SIGMA_MCP_ALLOW_DEPLOY": "false"
      }
    }
  }
}`;

/**
 * "External agents (MCP)" panel — a read-only template for pointing Claude Desktop /
 * Code at Babel's stdio MCP server. Static on purpose: it must never read or display
 * the real .mcp.json (which holds credentials).
 */
export const McpConnectionInfo: React.FC = () => {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(MCP_JSON_TEMPLATE).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <EuiPanel hasBorder paddingSize="m">
      <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
        <EuiFlexItem><EuiTitle size="xs"><h4>External agents (MCP)</h4></EuiTitle></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiBadge color="default">Claude Desktop / Code</EuiBadge></EuiFlexItem>
      </EuiFlexGroup>

      <EuiText size="s" color="subdued">
        Babel ships a Model Context Protocol (MCP) server that exposes its SIGMA tools (convert,
        validate, test, draft, explain, improve, search, deploy …) to an external agent such as
        Claude Desktop or Claude Code. The agent's own model does the reasoning, so no in-cluster
        or local model is required. Add the snippet below to your MCP client config (e.g. a project
        <code> .mcp.json</code>), adjusting the paths and Kibana password.
      </EuiText>
      <EuiSpacer size="s" />

      <div style={{ position: 'relative', borderRadius: 4, background: 'rgba(0,0,0,0.025)', border: '1px solid rgba(0,0,0,0.08)' }}>
        <pre style={{ margin: 0, padding: 12, fontSize: 11, overflowX: 'auto', whiteSpace: 'pre' }}>{MCP_JSON_TEMPLATE}</pre>
        <EuiButtonIcon
          aria-label="Copy MCP config"
          iconType={copied ? 'check' : 'copyClipboard'}
          size="s"
          onClick={copy}
          style={{ position: 'absolute', top: 6, right: 6, background: 'rgba(255,255,255,0.85)', borderRadius: 4 }}
        />
      </div>

      <EuiSpacer size="s" />
      <EuiCallOut size="s" color="primary" iconType="lock" title="Holds credentials">
        The MCP config stores a Kibana password — keep it out of version control (Babel git-ignores
        <code> .mcp.json</code>) and scope the account to least privilege. See SECURITY.md §10.
      </EuiCallOut>
    </EuiPanel>
  );
};

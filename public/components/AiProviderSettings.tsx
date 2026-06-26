import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFieldPassword,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTitle,
  EuiBadge,
} from '@elastic/eui';
import { ApiService, AiProviderConfig, KibanaConnector } from '../services/api';

const PROVIDER_OPTIONS = [
  { value: 'anthropic',    text: 'Anthropic Claude' },
  { value: 'openai',       text: 'OpenAI' },
  { value: 'openai_compat', text: 'OpenAI-compatible (Ollama, LM Studio, llama.cpp …)' },
  { value: 'connector',   text: 'Elastic Connector (Stack Management)' },
];

const PROVIDER_DEFAULTS: Record<string, Partial<AiProviderConfig>> = {
  anthropic:    { model: 'claude-sonnet-4-6' },
  openai:       { base_url: 'https://api.openai.com/v1', model: 'gpt-4o' },
  openai_compat: { base_url: 'http://host.docker.internal:11434/v1', model: 'llama3.2' },
  connector:    {},
};

const CONNECTOR_TYPE_LABELS: Record<string, string> = {
  '.gen-ai':    'OpenAI',
  '.bedrock':   'AWS Bedrock',
  '.gemini':    'Google Gemini',
  '.inference': 'Elastic Inference',
  '.d3security': 'D3 Security',
};

interface AiProviderSettingsProps {
  apiService: ApiService;
}

export const AiProviderSettings: React.FC<AiProviderSettingsProps> = ({ apiService }) => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [cfg, setCfg] = useState<AiProviderConfig>({ provider: 'anthropic' });
  const [connectors, setConnectors] = useState<KibanaConnector[]>([]);
  const [loadingConnectors, setLoadingConnectors] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiService.getAiProvider();
      if (res.success && res.data) setCfg(res.data);
    } catch { /* use default */ } finally {
      setLoading(false);
    }
  }, [apiService]);

  const loadConnectors = useCallback(async () => {
    setLoadingConnectors(true);
    try {
      const res = await apiService.getConnectors();
      setConnectors(res.connectors ?? []);
    } catch { setConnectors([]); } finally {
      setLoadingConnectors(false);
    }
  }, [apiService]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (cfg.provider === 'connector') loadConnectors();
  }, [cfg.provider, loadConnectors]);

  const handleProviderChange = (provider: AiProviderConfig['provider']) => {
    const defaults = PROVIDER_DEFAULTS[provider] ?? {};
    setCfg(prev => ({
      provider,
      model:          defaults.model          ?? prev.model,
      base_url:       defaults.base_url       ?? prev.base_url,
      api_key:        prev.api_key,
      connector_id:   prev.connector_id,
      connector_type: prev.connector_type,
      connector_name: prev.connector_name,
    }));
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      await apiService.setAiProvider(cfg);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <EuiLoadingSpinner />;

  const connectorOptions = [
    { value: '', text: '— select a connector —' },
    ...connectors.map(c => ({
      value: c.id,
      text: `${c.name} (${CONNECTOR_TYPE_LABELS[c.connector_type_id] ?? c.connector_type_id})`,
    })),
  ];

  return (
    <EuiPanel hasBorder paddingSize="m">
      <EuiFlexGroup alignItems="center" gutterSize="s">
        <EuiFlexItem>
          <EuiTitle size="xxs"><h5>LLM Provider</h5></EuiTitle>
        </EuiFlexItem>
        {saved && <EuiFlexItem grow={false}><EuiBadge color="success">Saved</EuiBadge></EuiFlexItem>}
      </EuiFlexGroup>
      <EuiText size="xs" color="subdued" style={{ marginBottom: 12 }}>
        Choose the model that powers rule drafting, explanation, and improvement.
        Keys are stored in Elasticsearch and never exposed to the browser after saving.
      </EuiText>

      <EuiFormRow label="Provider" fullWidth>
        <EuiSelect
          fullWidth
          options={PROVIDER_OPTIONS}
          value={cfg.provider}
          onChange={e => handleProviderChange(e.target.value as AiProviderConfig['provider'])}
        />
      </EuiFormRow>

      <EuiSpacer size="s" />

      {/* Anthropic */}
      {cfg.provider === 'anthropic' && (
        <>
          <EuiFormRow label="API Key" helpText="sk-ant-…" fullWidth>
            <EuiFieldPassword
              fullWidth
              type="dual"
              placeholder="sk-ant-api03-…"
              value={cfg.api_key ?? ''}
              onChange={e => setCfg(c => ({ ...c, api_key: e.target.value }))}
            />
          </EuiFormRow>
          <EuiFormRow label="Model" fullWidth>
            <EuiFieldText
              fullWidth
              value={cfg.model ?? 'claude-sonnet-4-6'}
              onChange={e => setCfg(c => ({ ...c, model: e.target.value }))}
            />
          </EuiFormRow>
        </>
      )}

      {/* OpenAI */}
      {cfg.provider === 'openai' && (
        <>
          <EuiFormRow label="API Key" helpText="sk-…" fullWidth>
            <EuiFieldPassword
              fullWidth
              type="dual"
              placeholder="sk-…"
              value={cfg.api_key ?? ''}
              onChange={e => setCfg(c => ({ ...c, api_key: e.target.value }))}
            />
          </EuiFormRow>
          <EuiFormRow label="Model" fullWidth>
            <EuiFieldText
              fullWidth
              value={cfg.model ?? 'gpt-4o'}
              onChange={e => setCfg(c => ({ ...c, model: e.target.value }))}
            />
          </EuiFormRow>
          <EuiFormRow label="Base URL" helpText="Leave default for OpenAI. Use Azure endpoint for Azure OpenAI." fullWidth>
            <EuiFieldText
              fullWidth
              value={cfg.base_url ?? 'https://api.openai.com/v1'}
              onChange={e => setCfg(c => ({ ...c, base_url: e.target.value }))}
            />
          </EuiFormRow>
        </>
      )}

      {/* OpenAI-compatible (Ollama, LM Studio, etc.) */}
      {cfg.provider === 'openai_compat' && (
        <>
          <EuiCallOut size="s" color="primary" iconType="iInCircle" title="Local model via Ollama">
            Run <code>ollama serve</code> on your host. The sigma-api container reaches it at{' '}
            <code>http://host.docker.internal:11434/v1</code>. No API key needed for Ollama.
          </EuiCallOut>
          <EuiSpacer size="s" />
          <EuiFormRow label="Base URL" fullWidth>
            <EuiFieldText
              fullWidth
              value={cfg.base_url ?? 'http://host.docker.internal:11434/v1'}
              onChange={e => setCfg(c => ({ ...c, base_url: e.target.value }))}
            />
          </EuiFormRow>
          <EuiFormRow label="Model name" helpText="Must be pulled in Ollama, e.g. llama3.2, mistral, codestral" fullWidth>
            <EuiFieldText
              fullWidth
              value={cfg.model ?? 'llama3.2'}
              onChange={e => setCfg(c => ({ ...c, model: e.target.value }))}
            />
          </EuiFormRow>
          <EuiFormRow label="API Key" helpText="Optional. Leave blank for Ollama / local endpoints." fullWidth>
            <EuiFieldPassword
              fullWidth
              type="dual"
              placeholder="(blank for Ollama)"
              value={cfg.api_key ?? ''}
              onChange={e => setCfg(c => ({ ...c, api_key: e.target.value }))}
            />
          </EuiFormRow>
        </>
      )}

      {/* Elastic Connector */}
      {cfg.provider === 'connector' && (
        <>
          <EuiCallOut size="s" color="primary" iconType="link" title="Uses a Kibana connector">
            Select a connector configured in Stack Management → Connectors. Supports OpenAI (.gen-ai),
            AWS Bedrock (.bedrock), Google Gemini (.gemini), and Elastic Inference (.inference).
            No additional API key needed — credentials live in the connector.
          </EuiCallOut>
          <EuiSpacer size="s" />
          {loadingConnectors ? (
            <EuiFlexGroup><EuiFlexItem grow={false}><EuiLoadingSpinner size="s" /></EuiFlexItem>
              <EuiFlexItem><EuiText size="s" color="subdued">Loading connectors…</EuiText></EuiFlexItem>
            </EuiFlexGroup>
          ) : connectors.length === 0 ? (
            <EuiCallOut size="s" color="warning" iconType="warning" title="No LLM connectors found">
              Go to Stack Management → Connectors and create an OpenAI, Bedrock, Gemini, or Elastic Inference connector first.
            </EuiCallOut>
          ) : (
            <EuiFormRow label="Connector" fullWidth>
              <EuiSelect
                fullWidth
                options={connectorOptions}
                value={cfg.connector_id ?? ''}
                onChange={e => {
                  const found = connectors.find(c => c.id === e.target.value);
                  setCfg(c => ({
                    ...c,
                    connector_id: e.target.value || undefined,
                    connector_type: found?.connector_type_id,
                    connector_name: found?.name,
                  }));
                }}
              />
            </EuiFormRow>
          )}
          {connectors.length > 0 && (
            <EuiButtonEmpty size="xs" iconType="refresh" onClick={loadConnectors} style={{ marginTop: 4 }}>
              Refresh connectors
            </EuiButtonEmpty>
          )}
        </>
      )}

      <EuiSpacer size="m" />

      {error && (
        <>
          <EuiCallOut title={error} color="danger" iconType="error" size="s" />
          <EuiSpacer size="s" />
        </>
      )}

      <EuiButton fill size="s" onClick={handleSave} isLoading={saving}>
        Save Provider Settings
      </EuiButton>
    </EuiPanel>
  );
};

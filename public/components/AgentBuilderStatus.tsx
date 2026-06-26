import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { ApiService, AgentBuilderStatus as Status } from '../services/api';

interface Props {
  apiService: ApiService;
}

/**
 * "Elastic AI Assistant (Agent Builder)" panel — registers/removes Babel's SIGMA
 * agents in Elastic's native Agent Builder. Degrades gracefully when the Agent
 * Builder API isn't available on the target Kibana (feature-gated / wrong license).
 */
export const AgentBuilderStatus: React.FC<Props> = ({ apiService }) => {
  const [status, setStatus] = useState<Status | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setStatus(await apiService.getAgentBuilderStatus());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load Agent Builder status');
    } finally {
      setLoading(false);
    }
  }, [apiService]);

  useEffect(() => { load(); }, [load]);

  const register = useCallback(async () => {
    setBusy(true); setError(null); setNotice(null);
    try {
      const res = await apiService.setupAgentBuilder();
      const failed = res.agents.filter(a => a.status !== 'created');
      if (failed.length) {
        setError(`Some agents failed: ${failed.map(f => `${f.id} (${f.message ?? f.status})`).join(', ')}`);
      } else {
        setNotice(`Registered ${res.agents.length} SIGMA agents in Elastic's AI Assistant.`);
      }
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to register agents');
    } finally {
      setBusy(false);
    }
  }, [apiService, load]);

  const remove = useCallback(async () => {
    setBusy(true); setError(null); setNotice(null);
    try {
      await apiService.removeAgentBuilder();
      setNotice("Removed Babel's SIGMA agents from Elastic's AI Assistant.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to remove agents');
    } finally {
      setBusy(false);
    }
  }, [apiService, load]);

  const anyRegistered = status?.agents.some(a => a.registered) ?? false;

  return (
    <EuiPanel hasBorder paddingSize="m">
      <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
        <EuiFlexItem>
          <EuiTitle size="xs"><h4>Elastic AI Assistant (Agent Builder)</h4></EuiTitle>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          {loading ? <EuiLoadingSpinner size="m" />
            : status?.available
              ? <EuiBadge color={anyRegistered ? 'success' : 'default'}>{anyRegistered ? 'Registered' : 'Available'}</EuiBadge>
              : <EuiBadge color="warning">Not available</EuiBadge>}
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiText size="s" color="subdued">
        Register Babel's SIGMA detection-engineering agents into Elastic's native AI Assistant.
        Once registered, analysts can use them from Kibana's Assistant — powered by whichever LLM
        connector Elastic is configured with — without Babel's own panel or a local model.
      </EuiText>
      <EuiSpacer size="s" />

      {!loading && !status?.available && (
        <EuiCallOut size="s" color="warning" iconType="iInCircle" title="Agent Builder isn't available on this Kibana">
          {status?.reason ?? 'The Elastic Agent Builder API could not be reached. It may be disabled or require a feature flag/license.'}
        </EuiCallOut>
      )}

      {status?.available && (
        <>
          <EuiFlexGroup gutterSize="s" wrap responsive={false}>
            {status.agents.map(a => (
              <EuiFlexItem key={a.id} grow={false}>
                <EuiBadge color={a.registered ? 'success' : 'hollow'}>{a.name}</EuiBadge>
              </EuiFlexItem>
            ))}
          </EuiFlexGroup>
          <EuiSpacer size="m" />
          <EuiFlexGroup gutterSize="s" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiButton size="s" fill iconType="plusInCircle" onClick={register} isLoading={busy} isDisabled={busy}>
                {anyRegistered ? 'Re-register agents' : 'Register agents'}
              </EuiButton>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton size="s" color="danger" iconType="trash" onClick={remove} isLoading={busy} isDisabled={busy || !anyRegistered}>
                Remove
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </>
      )}

      {error && (<><EuiSpacer size="s" /><EuiCallOut size="s" color="danger" iconType="error" title={error} /></>)}
      {notice && !error && (<><EuiSpacer size="s" /><EuiCallOut size="s" color="success" iconType="check" title={notice} /></>)}
    </EuiPanel>
  );
};

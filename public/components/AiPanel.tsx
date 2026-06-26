import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
  EuiFlyout,
  EuiFlyoutHeader,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiTitle,
  EuiTabs,
  EuiTab,
  EuiTextArea,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiSpacer,
  EuiCallOut,
  EuiLoadingSpinner,
  EuiFlexGroup,
  EuiFlexItem,
  EuiSelect,
  EuiText,
  EuiCode,
  EuiAccordion,
  EuiBadge,
  EuiToolTip,
} from '@elastic/eui';
import { AIResult, AlertSummary } from '../types';
import { ApiService } from '../services/api';

// ── Helpers ────────────────────────────────────────────────────────────────────

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const URL_RE  = /https?:\/\/\S+/;
const SIGMA_START_KEYS = ['title:', 'id:', 'status:', 'logsource:', 'detection:'];

function uuidv4(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

/** Fix known issues in AI-generated SIGMA YAML before it hits the converter. */
function sanitiseAiYaml(raw: string): { yaml: string; warnings: string[] } {
  const warnings: string[] = [];
  let text = raw;

  // 1. Extract from code fences if present
  const fenceMatch = text.match(/```(?:yaml|yml)?\s*\n([\s\S]*?)(?:```|$)/i);
  if (fenceMatch) {
    text = fenceMatch[1].trim();
    warnings.push('Removed markdown code fence from AI output');
  } else {
    // 2. Strip leading prose — find where YAML actually starts
    const lines = text.split('\n');
    const firstYamlLine = lines.findIndex(l => SIGMA_START_KEYS.some(k => l.trim().startsWith(k)));
    if (firstYamlLine > 0) {
      text = lines.slice(firstYamlLine).join('\n').trim();
      warnings.push('Stripped leading prose text from AI output');
    }
  }

  // 3. Fix invalid id: values
  const out: string[] = [];
  for (const line of text.split('\n')) {
    const idMatch = line.match(/^(id:\s*)(.+)$/);
    if (idMatch) {
      const val = idMatch[2].trim().replace(/^['"]|['"]$/g, '');
      if (!UUID_RE.test(val)) {
        const fresh = uuidv4();
        out.push(`id: ${fresh}`);
        warnings.push(`id field "${val}" was not a valid UUID — replaced with ${fresh}`);
        continue;
      }
    }
    out.push(line);
  }

  return { yaml: out.join('\n').trim(), warnings };
}

/** Extract the first SIGMA YAML block from an assistant message. */
function extractYamlFromContent(content: string): string | null {
  const m = content.match(/```(?:yaml|yml)?\s*\n([\s\S]*?)```/i);
  return m ? m[1].trim() : null;
}

// ── Chat bubble ────────────────────────────────────────────────────────────────

interface ChatMessage { role: 'user' | 'assistant'; content: string; }

interface ChatBubbleProps {
  message: ChatMessage;
  onLoadRule: (yaml: string) => void;
  onClose: () => void;
}

function ChatBubble({ message, onLoadRule, onClose }: ChatBubbleProps) {
  const isUser = message.role === 'user';
  const yaml = !isUser ? extractYamlFromContent(message.content) : null;

  const renderContent = () => {
    // Split on fenced code blocks so we can render them distinctly
    const parts = message.content.split(/(```(?:yaml|yml|bash|)?\n[\s\S]*?```)/gi);
    return parts.map((part, i) => {
      const codeMatch = part.match(/^```(yaml|yml|bash|)?\n([\s\S]*?)```$/i);
      if (codeMatch) {
        return (
          <EuiCode
            key={i}
            language={codeMatch[1] || 'yaml'}
            style={{ display: 'block', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 11, marginTop: 6, marginBottom: 4 }}
          >
            {codeMatch[2]}
          </EuiCode>
        );
      }
      return (
        <span key={i} style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{part}</span>
      );
    });
  };

  return (
    <div style={{ display: 'flex', justifyContent: isUser ? 'flex-end' : 'flex-start', marginBottom: 12 }}>
      <div style={{
        maxWidth: '88%',
        minWidth: 0,
        overflowWrap: 'anywhere',
        wordBreak: 'break-word',
        padding: '10px 14px',
        borderRadius: isUser ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
        background: isUser ? '#006BB4' : '#F5F7FA',
        color: isUser ? '#fff' : 'inherit',
        fontSize: 13,
        lineHeight: 1.5,
        border: isUser ? 'none' : '1px solid #D3DAE6',
      }}>
        {renderContent()}
        {yaml && (
          <div style={{ marginTop: 10 }}>
            <EuiButton
              size="s"
              fill
              onClick={() => { onLoadRule(yaml); onClose(); }}
            >
              Load into Editor
            </EuiButton>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

type Tab = 'ioc' | 'alert' | 'explain' | 'improve' | 'chat';

interface AiPanelProps {
  isOpen: boolean;
  onClose: () => void;
  currentRuleYaml: string;
  onLoadRule: (yaml: string) => void;
  apiService: ApiService;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'danger', high: 'danger', medium: 'warning', low: 'primary',
};

export const AiPanel: React.FC<AiPanelProps> = ({
  isOpen, onClose, currentRuleYaml, onLoadRule, apiService,
}) => {
  const [activeTab, setActiveTab] = useState<Tab>('ioc');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<AIResult | null>(null);
  const [sanitiseWarnings, setSanitiseWarnings] = useState<string[]>([]);

  // IOC tab
  const [iocText, setIocText] = useState('');
  const [logsourceHint, setLogsourceHint] = useState('');

  // Alert tab
  const [alertSource, setAlertSource] = useState<'kibana' | 'so'>('kibana');
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [alertsLoaded, setAlertsLoaded] = useState(false);
  const [selectedAlertId, setSelectedAlertId] = useState('');

  // Chat tab
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  const reset = useCallback(() => {
    setResult(null);
    setIsLoading(false);
    setSanitiseWarnings([]);
  }, []);

  // Auto-scroll chat to bottom on new messages
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages, chatLoading]);

  // Sanitise AI-generated YAML whenever a new result with rule_yaml arrives
  useEffect(() => {
    if (result?.rule_yaml) {
      const { yaml, warnings } = sanitiseAiYaml(result.rule_yaml);
      if (warnings.length > 0) {
        setSanitiseWarnings(warnings);
        setResult(prev => prev ? { ...prev, rule_yaml: yaml } : prev);
      }
    }
  }, [result?.rule_yaml]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleTabChange = useCallback((tab: Tab) => {
    setActiveTab(tab);
    reset();
  }, [reset]);

  const loadAlerts = useCallback(async () => {
    try {
      const res = await apiService.listAlerts(alertSource);
      setAlerts((res as any).alerts ?? []);
      setAlertsLoaded(true);
    } catch {
      setAlerts([]);
      setAlertsLoaded(true);
    }
  }, [apiService, alertSource]);

  const handleIOCDraft = useCallback(async () => {
    const iocs = iocText.split('\n').map(l => l.trim()).filter(Boolean);
    if (!iocs.length) return;
    setIsLoading(true);
    setResult(null);
    try {
      const res = await apiService.aiDraftFromIOCs(iocs, undefined, logsourceHint || undefined);
      setResult(res as AIResult);
    } catch (e: unknown) {
      setResult({ success: false, message: e instanceof Error ? e.message : 'Request failed' });
    } finally {
      setIsLoading(false);
    }
  }, [apiService, iocText, logsourceHint]);

  const handleAlertDraft = useCallback(async () => {
    if (!selectedAlertId) return;
    setIsLoading(true);
    setResult(null);
    try {
      const res = await apiService.aiDraftFromAlert(selectedAlertId, alertSource);
      setResult(res as AIResult);
    } catch (e: unknown) {
      setResult({ success: false, message: e instanceof Error ? e.message : 'Request failed' });
    } finally {
      setIsLoading(false);
    }
  }, [apiService, selectedAlertId, alertSource]);

  const handleExplain = useCallback(async () => {
    if (!currentRuleYaml) return;
    setIsLoading(true);
    setResult(null);
    try {
      const res = await apiService.aiExplain(currentRuleYaml);
      setResult(res as AIResult);
    } catch (e: unknown) {
      setResult({ success: false, message: e instanceof Error ? e.message : 'Request failed' });
    } finally {
      setIsLoading(false);
    }
  }, [apiService, currentRuleYaml]);

  const handleImprove = useCallback(async () => {
    if (!currentRuleYaml) return;
    setIsLoading(true);
    setResult(null);
    try {
      const res = await apiService.aiImprove(currentRuleYaml);
      setResult(res as AIResult);
    } catch (e: unknown) {
      setResult({ success: false, message: e instanceof Error ? e.message : 'Request failed' });
    } finally {
      setIsLoading(false);
    }
  }, [apiService, currentRuleYaml]);

  const handleSendChat = useCallback(async () => {
    const content = chatInput.trim();
    if (!content || chatLoading) return;

    const userMsg: ChatMessage = { role: 'user', content };
    const updatedMessages = [...chatMessages, userMsg];
    setChatMessages(updatedMessages);
    setChatInput('');
    setChatLoading(true);

    try {
      const res = await apiService.aiChat(
        updatedMessages.map(m => ({ role: m.role, content: m.content })),
        currentRuleYaml || undefined,
      );
      const reply = (res as any).reply ?? (res as any).message ?? 'No response received.';
      setChatMessages(prev => [...prev, { role: 'assistant', content: reply }]);
    } catch (e: unknown) {
      setChatMessages(prev => [...prev, {
        role: 'assistant',
        content: `Error: ${e instanceof Error ? e.message : 'Request failed'}`,
      }]);
    } finally {
      setChatLoading(false);
    }
  }, [chatInput, chatMessages, chatLoading, apiService, currentRuleYaml]);

  const handleChatKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendChat();
    }
  }, [handleSendChat]);

  if (!isOpen) return null;

  const hasUrl = URL_RE.test(chatInput);

  return (
    <EuiFlyout onClose={onClose} size="m" aria-labelledby="ai-panel-title">
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="m">
          <h2 id="ai-panel-title">AI Detection Assistant</h2>
        </EuiTitle>
        <EuiSpacer size="s" />
        <EuiTabs>
          {([
            { id: 'ioc',     label: 'IOC → Rule' },
            { id: 'alert',   label: 'Alert → Rule' },
            { id: 'explain', label: 'Explain' },
            { id: 'improve', label: 'Improve' },
            { id: 'chat',    label: 'Chat' },
          ] as { id: Tab; label: string }[]).map(tab => (
            <EuiTab
              key={tab.id}
              isSelected={activeTab === tab.id}
              onClick={() => handleTabChange(tab.id)}
            >
              {tab.label}
            </EuiTab>
          ))}
        </EuiTabs>
      </EuiFlyoutHeader>

      <EuiFlyoutBody>
        {/* ── IOC → Rule ── */}
        {activeTab === 'ioc' && (
          <>
            <EuiText size="s" color="subdued">
              <p>Enter IOCs (one per line): IPs, hashes, process names, file paths, registry keys, domains.</p>
            </EuiText>
            <EuiSpacer size="s" />
            <EuiTextArea
              placeholder={'192.168.1.100\nmalware.exe\nHKEY_LOCAL_MACHINE\\Software\\Evil'}
              value={iocText}
              onChange={e => setIocText(e.target.value)}
              rows={6}
              fullWidth
            />
            <EuiSpacer size="s" />
            <EuiSelect
              prepend="Logsource hint"
              options={[
                { value: '', text: 'Auto-detect' },
                { value: 'process_creation',  text: 'process_creation' },
                { value: 'network_connection', text: 'network_connection' },
                { value: 'file_event',        text: 'file_event' },
                { value: 'registry_event',    text: 'registry_event' },
                { value: 'dns_query',         text: 'dns_query' },
                { value: 'webserver',         text: 'webserver' },
              ]}
              value={logsourceHint}
              onChange={e => setLogsourceHint(e.target.value)}
            />
            <EuiSpacer size="m" />
            <EuiButton onClick={handleIOCDraft} isLoading={isLoading} isDisabled={!iocText.trim()} fill>
              Draft Rule
            </EuiButton>
          </>
        )}

        {/* ── Alert → Rule ── */}
        {activeTab === 'alert' && (
          <>
            <EuiFlexGroup gutterSize="s" alignItems="center">
              <EuiFlexItem grow={false}>
                <EuiSelect
                  options={[
                    { value: 'kibana', text: 'Kibana Security' },
                    { value: 'so',     text: 'Security Onion' },
                  ]}
                  value={alertSource}
                  onChange={e => { setAlertSource(e.target.value as 'kibana' | 'so'); setAlertsLoaded(false); setAlerts([]); }}
                />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton onClick={loadAlerts} size="s">Load Alerts</EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="m" />

            {alertsLoaded && alerts.length === 0 && (
              <EuiCallOut title="No recent alerts found" color="warning" iconType="warning" size="s" />
            )}

            {alerts.map(alert => (
              <div
                key={alert.id}
                onClick={() => setSelectedAlertId(alert.id)}
                style={{
                  padding: '8px 12px', marginBottom: 6, borderRadius: 4, cursor: 'pointer',
                  border: `1px solid ${selectedAlertId === alert.id ? '#006BB4' : '#D3DAE6'}`,
                  background: selectedAlertId === alert.id ? '#EBF5FF' : 'transparent',
                }}
              >
                <EuiFlexGroup gutterSize="s" alignItems="center">
                  <EuiFlexItem>
                    <EuiText size="s"><strong>{alert.rule_name ?? alert.id}</strong></EuiText>
                    <EuiText size="xs" color="subdued">{alert.host_name} · {alert.timestamp?.slice(0, 19)}</EuiText>
                  </EuiFlexItem>
                  {alert.severity && (
                    <EuiFlexItem grow={false}>
                      <EuiBadge color={SEVERITY_COLOR[alert.severity] ?? 'default'}>{alert.severity}</EuiBadge>
                    </EuiFlexItem>
                  )}
                  {alert.event_module && (
                    <EuiFlexItem grow={false}>
                      <EuiBadge color="hollow">{alert.event_module}</EuiBadge>
                    </EuiFlexItem>
                  )}
                </EuiFlexGroup>
              </div>
            ))}

            <EuiSpacer size="m" />
            <EuiButton onClick={handleAlertDraft} isLoading={isLoading} isDisabled={!selectedAlertId} fill>
              Draft Rule from Alert
            </EuiButton>
          </>
        )}

        {/* ── Explain ── */}
        {activeTab === 'explain' && (
          <>
            <EuiText size="s" color="subdued">
              <p>Explains the rule currently loaded in the YAML editor in plain English.</p>
            </EuiText>
            <EuiSpacer size="m" />
            <EuiButton onClick={handleExplain} isLoading={isLoading} isDisabled={!currentRuleYaml} fill>
              Explain Rule
            </EuiButton>
          </>
        )}

        {/* ── Improve ── */}
        {activeTab === 'improve' && (
          <>
            <EuiText size="s" color="subdued">
              <p>Analyses the current rule against your live ES field mappings and suggests improvements.
              The improved YAML can be loaded directly into the editor.</p>
            </EuiText>
            <EuiSpacer size="m" />
            <EuiButton onClick={handleImprove} isLoading={isLoading} isDisabled={!currentRuleYaml} fill>
              Improve Rule
            </EuiButton>
          </>
        )}

        {/* ── Chat ── */}
        {activeTab === 'chat' && (
          <>
            {chatMessages.length === 0 ? (
              <EuiText size="s" color="subdued">
                <p>Ask about detection engineering, paste a CVE or threat report URL to draft a
                SIGMA rule automatically, or describe suspicious behaviour you want to detect.</p>
                {currentRuleYaml && (
                  <p style={{ marginTop: 4 }}>
                    <EuiBadge color="primary">Rule context active</EuiBadge>
                    {' '}The rule in your editor is included as context on every message.
                  </p>
                )}
              </EuiText>
            ) : (
              <>
                <EuiFlexGroup justifyContent="flexEnd" gutterSize="s">
                  <EuiFlexItem grow={false}>
                    <EuiButtonEmpty
                      size="xs"
                      iconType="trash"
                      color="danger"
                      onClick={() => setChatMessages([])}
                    >
                      Clear conversation
                    </EuiButtonEmpty>
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiSpacer size="s" />
              </>
            )}

            <div style={{ marginTop: chatMessages.length ? 0 : 16 }}>
              {chatMessages.map((msg, i) => (
                <ChatBubble key={i} message={msg} onLoadRule={onLoadRule} onClose={onClose} />
              ))}
              {chatLoading && (
                <div style={{ display: 'flex', justifyContent: 'flex-start', marginBottom: 12 }}>
                  <div style={{
                    padding: '10px 14px',
                    borderRadius: '16px 16px 16px 4px',
                    background: '#F5F7FA',
                    border: '1px solid #D3DAE6',
                  }}>
                    <EuiLoadingSpinner size="m" />
                  </div>
                </div>
              )}
              <div ref={chatBottomRef} />
            </div>
          </>
        )}

        {/* ── Shared results (non-chat tabs) ── */}
        {activeTab !== 'chat' && (
          <>
            {isLoading && (
              <>
                <EuiSpacer size="l" />
                <EuiFlexGroup justifyContent="center">
                  <EuiFlexItem grow={false}><EuiLoadingSpinner size="l" /></EuiFlexItem>
                </EuiFlexGroup>
              </>
            )}

            {result && !isLoading && (
              <>
                <EuiSpacer size="l" />
                {!result.success && (
                  <EuiCallOut title={result.message ?? 'Request failed'} color="danger" iconType="error" size="s" />
                )}
                {sanitiseWarnings.length > 0 && (
                  <EuiCallOut title="Rule auto-corrected" color="warning" iconType="wrench" size="s">
                    {sanitiseWarnings.map((w, i) => <p key={i}>{w}</p>)}
                  </EuiCallOut>
                )}

                {result.explanation && (
                  <EuiText size="s">
                    <div style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{result.explanation}</div>
                  </EuiText>
                )}

                {result.rule_yaml && (
                  <>
                    <EuiAccordion id="ai-yaml" buttonContent="Generated SIGMA Rule" initialIsOpen>
                      <EuiCode language="yaml" style={{ display: 'block', whiteSpace: 'pre', overflowX: 'auto', fontSize: 12, padding: 12 }}>
                        {result.rule_yaml}
                      </EuiCode>
                    </EuiAccordion>

                    {result.changes && (
                      <>
                        <EuiSpacer size="s" />
                        <EuiAccordion id="ai-changes" buttonContent="Changes made">
                          <EuiText size="s">
                            <div style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{result.changes}</div>
                          </EuiText>
                        </EuiAccordion>
                      </>
                    )}
                  </>
                )}
              </>
            )}
          </>
        )}
      </EuiFlyoutBody>

      {/* ── Footer ── */}
      {activeTab === 'chat' ? (
        <EuiFlyoutFooter>
          <EuiFlexGroup gutterSize="s" alignItems="flexEnd">
            <EuiFlexItem>
              <EuiTextArea
                placeholder="Ask a question, paste a CVE URL, or describe behaviour to detect… (Shift+Enter for newline)"
                value={chatInput}
                onChange={e => setChatInput(e.target.value)}
                onKeyDown={handleChatKeyDown}
                rows={2}
                fullWidth
                resize="none"
                compressed
              />
              {hasUrl && (
                <EuiText size="xs" color="subdued" style={{ marginTop: 3 }}>
                  URL detected — page content will be fetched automatically
                </EuiText>
              )}
            </EuiFlexItem>
            <EuiFlexItem grow={false} style={{ paddingBottom: hasUrl ? 20 : 0 }}>
              <EuiButton
                fill
                onClick={handleSendChat}
                isLoading={chatLoading}
                isDisabled={!chatInput.trim()}
                iconType="editorComment"
              >
                Send
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlyoutFooter>
      ) : result?.rule_yaml ? (
        <EuiFlyoutFooter>
          <EuiFlexGroup justifyContent="spaceBetween">
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty onClick={reset}>Clear</EuiButtonEmpty>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton fill onClick={() => { onLoadRule(result.rule_yaml!); onClose(); }}>
                Load into Editor
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlyoutFooter>
      ) : null}
    </EuiFlyout>
  );
};

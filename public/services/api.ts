import { HttpService } from '../context/KibanaContext';
import {
  TestRunResult, DeployResult, ValidationResult, FieldSuggestion, ClusterHitsResult, CoverageResult,
  QualityScoreResult,
  EffectivenessResult, StaleRulesResult, SchemaDriftReport, RuleSourceResult,
  AIResult, AlertListResult,
} from '../types';

const BASE = '/api/babel';

export interface SigmaRepo {
  id: string;
  name: string;
  url: string;
  branch: string;
  rulesPath: string;
  enabled: boolean;
}

export interface ReposResult {
  success: boolean;
  data?: { repos: SigmaRepo[] };
  message?: string;
}

export interface SigmaDocResult {
  success: boolean;
  data?: { total: number; docs: Array<Record<string, unknown>> };
}

export interface TranslationResult {
  success: boolean;
  data?: { translation: string };
  message?: string;
}

export interface GitHubTokenResult {
  success: boolean;
  data?: { apiKey: string };
}

export interface SyncResult {
  success: boolean;
  synced?: number;
  total_found?: number;
  message?: string;
}

export interface DataSource {
  product: string;
  label: string;
  available: boolean;
  index_count: number;
  doc_count: number;
  indices: string[];
  categories: string[];
}

export function createApiService(http: HttpService) {
  return {
    searchRules(params: { search?: string; category?: string; mitre?: string; irPhase?: string; from?: number; size?: number }) {
      return http.get<SigmaDocResult>(`${BASE}/sigma-doc`, {
        query: params as Record<string, unknown>,
      });
    },

    translateRule(sigmaYaml: string, siemTo: string, pipeline = 'ecs_windows') {
      const bytes = new TextEncoder().encode(sigmaYaml);
      const sigmaText = btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''));
      return http.get<TranslationResult>(`${BASE}/sigma-translation`, {
        query: { sigmaText, siemTo, pipeline },
      });
    },

    addWatcher(watcherName: string, query: string, indexId?: string) {
      return http.post(`${BASE}/sigma-add-watcher`, {
        body: JSON.stringify({ watcherName, query, indexId }),
      });
    },

    getGitHubToken() {
      return http.post<GitHubTokenResult>(`${BASE}/get-github-token`);
    },

    setGitHubToken(token: string) {
      return http.post(`${BASE}/set-github-token`, {
        body: JSON.stringify({ apiKey: token }),
      });
    },

    syncFromGitHub(options?: { githubToken?: string; category?: string; limit?: number }) {
      return http.post<SyncResult>(`${BASE}/sync`, {
        body: JSON.stringify(options ?? {}),
      });
    },

    getRepos() {
      return http.get<ReposResult>(`${BASE}/repos`);
    },

    saveRepos(repos: SigmaRepo[]) {
      return http.post<{ success: boolean }>(`${BASE}/repos`, {
        body: JSON.stringify({ repos }),
      });
    },

    testRule(params: {
      ruleYaml: string;
      indexPattern?: string;
      timeframeHours?: number;
      pipeline?: string;
      queryFormat?: string;
    }) {
      return http.post<{ success: boolean; data?: TestRunResult; message?: string }>(`${BASE}/test-run`, {
        body: JSON.stringify({
          ruleYaml: params.ruleYaml,
          indexPattern: params.indexPattern ?? '*',
          timeframeHours: params.timeframeHours ?? 24,
          pipeline: params.pipeline ?? 'ecs_windows',
          queryFormat: params.queryFormat ?? 'eql',
        }),
      });
    },

    deployRule(params: {
      ruleYaml: string;
      format: string;
      pipeline: string;
      schedule?: string;
      enabled?: boolean;
    }) {
      return http.post<{ success: boolean; data?: DeployResult; message?: string }>(`${BASE}/deploy`, {
        body: JSON.stringify({
          ruleYaml: params.ruleYaml,
          format: params.format,
          pipeline: params.pipeline,
          schedule: params.schedule,
          enabled: params.enabled ?? false,
        }),
      });
    },

    getStatus() {
      return http.get(`${BASE}/status`);
    },

    validateRule(ruleYaml: string) {
      return http.post<ValidationResult>(`${BASE}/validate`, {
        body: JSON.stringify({ ruleYaml }),
      });
    },

    getFields(category?: string) {
      return http.get<Record<string, unknown>>(`${BASE}/fields`, {
        query: category ? { category } : {},
      });
    },

    suggestField(sigmaField: string) {
      return http.post<FieldSuggestion>(`${BASE}/fields/suggest`, {
        body: JSON.stringify({ sigmaField }),
      });
    },

    clusterHits(testRunId: string, topN = 5) {
      return http.post<{ success: boolean; data?: ClusterHitsResult; message?: string }>(
        `${BASE}/cluster-hits/${encodeURIComponent(testRunId)}`,
        { body: JSON.stringify({ topN }) }
      );
    },

    computeCoverage(ruleYamls: string[]) {
      return http.post<CoverageResult>(`${BASE}/coverage`, {
        body: JSON.stringify({ ruleYamls }),
      });
    },

    navigatorExport(ruleYamls: string[]) {
      return http.post<Record<string, unknown>>(`${BASE}/coverage/navigator-export`, {
        body: JSON.stringify({ ruleYamls }),
      });
    },

    irReadiness(scenario: string, ruleYamls: string[]) {
      return http.post<Record<string, unknown>>(`${BASE}/ir-readiness`, {
        body: JSON.stringify({ scenario, ruleYamls }),
      });
    },

    getRuleQuality(ruleYaml: string) {
      return http.post<QualityScoreResult>(`${BASE}/rules/quality`, {
        body: JSON.stringify({ ruleYaml }),
      });
    },

    getDataSources() {
      return http.get<{ sources: DataSource[] }>(`${BASE}/data-sources`);
    },

    getRuleEffectiveness(ruleTitle: string, limit = 20) {
      return http.get<EffectivenessResult>(`${BASE}/rules/effectiveness`, {
        query: { rule_title: ruleTitle, limit },
      });
    },

    getStaleRules(days = 30) {
      return http.get<StaleRulesResult>(`${BASE}/rules/stale`, {
        query: { days },
      });
    },

    snapshotSchema(indexPattern: string) {
      return http.post(`${BASE}/schema-drift/snapshot`, {
        body: JSON.stringify({ indexPattern }),
      });
    },

    snapshotSOSchemas() {
      return http.post(`${BASE}/schema-drift/snapshot/so`);
    },

    getSchemaDrift(indexPattern: string) {
      return http.get<SchemaDriftReport>(`${BASE}/schema-drift/report`, {
        query: { indexPattern },
      });
    },

    getRuleSource(kibanaRuleId: string) {
      return http.get<RuleSourceResult>(`${BASE}/rules/source`, {
        query: { kibanaRuleId },
      });
    },

    aiDraftFromIOCs(iocs: string[], indexPattern?: string, logsourceHint?: string) {
      return http.post<AIResult>(`${BASE}/ai/draft-from-iocs`, {
        body: JSON.stringify({ iocs, indexPattern, logsourceHint }),
      });
    },

    aiExplain(ruleYaml: string) {
      return http.post<AIResult>(`${BASE}/ai/explain`, {
        body: JSON.stringify({ ruleYaml }),
      });
    },

    aiImprove(ruleYaml: string, indexPattern?: string) {
      return http.post<AIResult>(`${BASE}/ai/improve`, {
        body: JSON.stringify({ ruleYaml, indexPattern }),
      });
    },

    aiDraftFromAlert(alertId: string, source: 'kibana' | 'so' = 'kibana') {
      return http.post<AIResult>(`${BASE}/ai/draft-from-alert`, {
        body: JSON.stringify({ alertId, source }),
      });
    },

    listAlerts(source: 'kibana' | 'so' = 'kibana', size = 20) {
      return http.get<AlertListResult>(`${BASE}/ai/alerts`, {
        query: { source, size },
      });
    },

    setupAgentBuilder() {
      return http.post(`${BASE}/agent-builder/setup`);
    },

    getAnthropicKey() {
      return http.get<{ success: boolean; data?: { masked: string; configured: boolean } }>(`${BASE}/anthropic-key`);
    },

    setAnthropicKey(apiKey: string) {
      return http.post<{ success: boolean }>(`${BASE}/anthropic-key`, {
        body: JSON.stringify({ apiKey }),
      });
    },

    getAiProvider() {
      return http.get<{ success: boolean; data?: AiProviderConfig }>(`${BASE}/ai/provider`);
    },

    setAiProvider(cfg: AiProviderConfig) {
      return http.post<{ success: boolean }>(`${BASE}/ai/provider`, {
        body: JSON.stringify(cfg),
      });
    },

    getConnectors() {
      return http.get<{ connectors: KibanaConnector[] }>(`${BASE}/connectors`);
    },

    aiChat(messages: Array<{ role: string; content: string }>, ruleContext?: string) {
      return http.post<{ success: boolean; reply?: string; message?: string }>(`${BASE}/ai/chat`, {
        body: JSON.stringify({ messages, ruleContext }),
      });
    },
  };
}

export interface AiProviderConfig {
  provider: 'anthropic' | 'openai' | 'openai_compat' | 'ollama' | 'connector';
  model?: string;
  base_url?: string;
  api_key?: string;
  connector_id?: string;
  connector_type?: string;
  connector_name?: string;
}

export interface KibanaConnector {
  id: string;
  name: string;
  connector_type_id: string;
}

export type ApiService = ReturnType<typeof createApiService>;

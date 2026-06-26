export type IrPhase = 'preparation' | 'detection' | 'containment' | 'eradication' | 'recovery' | 'post-incident';

export interface SigmaRule {
  title?: string;
  status?: string;
  description?: string;
  logsource?: Record<string, string>;
  detection?: Record<string, unknown>;
  level?: string;
  tags?: string[];
  'x-ir-phase'?: IrPhase;
  [key: string]: unknown;
}

export interface EventSample {
  event_id: string;
  timestamp: string;
  source: Record<string, unknown>;
}

export interface TestRunResult {
  test_run_id: string;
  hit_count: number;
  sample_events: EventSample[];
  timing_ms: number;
}

export interface DeployResult {
  rule_id: string;
  name: string;
  enabled: boolean;
  created_at: string;
}

export interface TranslationResult {
  success: boolean;
  data?: {
    translation: string;
    baseIndexId: string;
  };
}

export interface ValidationIssue {
  type: 'error' | 'warning';
  rule: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  issues: ValidationIssue[];
}

export interface EcsFieldEntry {
  field: string;
  type: string;
  description: string;
}

export interface FieldSuggestion {
  sigma_field: string;
  ecs_field?: string;
  confidence?: number;
  description?: string;
  live_fields: string[];
}

export interface ClusterBucket {
  value: string;
  count: number;
}

export interface ClusterField {
  field: string;
  buckets: ClusterBucket[];
}

export interface ClusterHitsResult {
  test_run_id: string;
  total_hits: number;
  clusters: ClusterField[];
}

export interface CoverageTechnique {
  id: string;
  name: string;
  tactic: string;
  tactic_display: string;
  rules: string[];
}

export interface CoverageResult {
  total_rules: number;
  parsed_rules: number;
  covered_techniques: number;
  covered_tactics: string[];
  techniques: CoverageTechnique[];
  by_tactic: Record<string, string[]>;
  uncovered_tactics: string[];
  rule_index: Record<string, string[]>;
}

export interface SigmaDoc {
  id: string;
  title: string;
  category?: string;
  [key: string]: unknown;
}

export interface QualityScoreResult {
  rule_title: string;
  score: number;
  reasons: string[];
}

export interface EffectivenessRecord {
  rule_title: string;
  rule_yaml_hash: string;
  test_run_id: string;
  hit_count: number;
  index_pattern: string;
  query_format: string;
  ran_at: string;
}

export interface EffectivenessResult {
  rule_title: string;
  records: EffectivenessRecord[];
}

export interface StaleRuleEntry {
  rule_title: string;
  last_run_at: string;
  total_runs: number;
  max_hits_in_window: number;
  stale_days: number;
}

export interface StaleRulesResult {
  stale_rules: StaleRuleEntry[];
  days: number;
}

export interface DriftedField {
  field: string;
  status: 'removed' | 'type_changed';
  previous_type?: string;
  current_type?: string;
}

export interface SchemaDriftReport {
  index_pattern: string;
  snapshot_taken_at?: string;
  checked_at: string;
  drifted_fields: DriftedField[];
  total_fields_snapshot: number;
  total_fields_current: number;
}

export interface RuleSourceResult {
  kibana_rule_id: string;
  rule_yaml: string;
  title: string;
  registered_at: string;
}

export interface AIResult {
  success: boolean;
  rule_yaml?: string;
  explanation?: string;
  changes?: string;
  source_type?: string;
  message?: string;
}

export interface AlertSummary {
  id: string;
  timestamp?: string;
  rule_name?: string;
  severity?: string;
  host_name?: string;
  event_module?: string;
}

export interface AlertListResult {
  alerts: AlertSummary[];
  index_pattern: string;
}


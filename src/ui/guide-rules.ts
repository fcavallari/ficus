import { ruleLevels, SEVERITY_RANK, type Rule, type Severity } from '../rules/rules';

/*
 * The guide's list of every rule, filtered and sorted in place. A rule whose findings vary (odd-location-exec can be
 * high, med or low) is shown under every severity it can reach, so filtering on "high" never hides a rule that can
 * raise a high finding.
 */

export const SEVERITIES: Severity[] = ['high', 'med', 'low'];

export type RuleOrder = 'severity' | 'stage' | 'name';
export const RULE_ORDERS: { id: RuleOrder; label: string }[] = [
  { id: 'severity', label: 'Severity' },
  { id: 'stage', label: 'Stage' },
  { id: 'name', label: 'Name' },
];

/** Whether a rule can raise a finding at any of these severities. */
export const ruleCanReach = (r: Rule, show: ReadonlySet<Severity>): boolean => ruleLevels(r).some(l => show.has(l));

const top = (r: Rule): number => SEVERITY_RANK[ruleLevels(r)[0]!];
const bottom = (r: Rule): number => SEVERITY_RANK[ruleLevels(r).at(-1)!];
const byTitle = (a: Rule, b: Rule): number => a.title.localeCompare(b.title);

/**
 * The rules to list. By severity: the highest level a rule can reach first, then the rule that never goes lower (always
 * high before high or med), then by title. By stage: the order of `stageOrder` (rule ids, stage by stage). By name: the
 * title, A to Z.
 */
export function listRules(rules: readonly Rule[], show: ReadonlySet<Severity>, order: RuleOrder, stageOrder: readonly string[]): Rule[] {
  const shown = rules.filter(r => ruleCanReach(r, show));
  if (order === 'name') return shown.sort(byTitle);
  if (order === 'stage') {
    const at = (r: Rule): number => { const i = stageOrder.indexOf(r.id); return i < 0 ? stageOrder.length : i; };
    return shown.sort((a, b) => at(a) - at(b) || byTitle(a, b));
  }
  return shown.sort((a, b) => top(b) - top(a) || bottom(b) - bottom(a) || byTitle(a, b));
}

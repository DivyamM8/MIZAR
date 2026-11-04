import { ErrorBox, Loading, Section, SeverityBadge } from "../components/ui";
import { useApi } from "../lib/hooks";
import type { Rule } from "../lib/types";

export function RulesPage() {
  const rules = useApi<Rule[]>("/api/rules");
  return (
    <Section title={`Detection rules (${rules.data?.length ?? "…"})`}>
      <p className="muted small">
        Base severity and confidence are starting points; each finding lists the modifiers that changed them. Rules are
        versioned YAML files and every run records which versions it used.
      </p>
      <ErrorBox error={rules.error} />
      {!rules.data && !rules.error ? <Loading /> : null}
      {rules.data?.map((rule) => (
        <details key={rule.rule_id} id={rule.rule_id} className="rule" open={window.location.hash === `#${rule.rule_id}`}>
          <summary>
            <strong>{rule.rule_id}</strong> <SeverityBadge severity={rule.base_severity} /> {rule.title}{" "}
            <span className="muted small">
              {rule.type} · {rule.attack.join(", ")} · v{rule.version}
            </span>
          </summary>
          <p>{rule.description}</p>
          <p className="small">
            Base confidence {rule.base_confidence}, evidence {rule.evidence_strength}, status {rule.status}.
          </p>
          {Object.keys(rule.params).length ? (
            <table className="compact">
              <thead>
                <tr>
                  <th>Parameter</th>
                  <th>Type</th>
                  <th>Default</th>
                  <th>Meaning</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(rule.params).map(([name, p]) => (
                  <tr key={name}>
                    <td>{name}</td>
                    <td>{p.type}</td>
                    <td>{String(p.default)}</td>
                    <td>{p.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </details>
      ))}
    </Section>
  );
}

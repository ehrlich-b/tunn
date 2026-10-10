"""Escape and render an offline observation report as static HTML."""
from html import escape

METRICS = {
    "dropped_out": "Dropouts", "activated": "Activation",
    "completed_useful_task": "Useful completion", "required_assistance": "Required assistance",
    "written_paid_intent": "Written paid intent", "payment_collected": "Collected payment",
    "repeat_on_two_later_days": "Voluntary useful return on two later days",
}


def cell(value):
    if value is None:
        return '<span class="missing">undefined (null)</span>'
    if type(value) is bool:
        return "yes" if value else "no"
    return escape(str(value), quote=True)


def table(headers, rows):
    return '<div class="table-wrap"><table><thead><tr>' + ''.join(f'<th scope="col">{escape(h)}</th>' for h in headers) + \
        '</tr></thead><tbody>' + ''.join('<tr>' + ''.join(f'<td>{cell(v)}</td>' for v in row) + '</tr>' for row in rows) + '</tbody></table></div>'


def render(report):
    sections = [f'<p class="notice">OFFLINE EVIDENCE REPORT · {cell(report["actual_observation_rows"])} asserted actual rows · '
                f'{cell(report["simulated_observation_rows"])} simulated rows · No launch or security approval.</p>',
                '<h1>Evidence before enthusiasm.</h1><p class="lede">Every original participant stays in the denominator. '
                'Simulation, activation, useful completion, intent, payment and repeat use are separate.</p>',
                f'<p class="fine">Frozen protocol: {cell(report["protocol_id"])}<br>Protocol SHA-256: '
                f'{cell(report["protocol_sha256"])}<br>Normalized input SHA-256: {cell(report["input_sha256"])}</p>']
    for name, result in report["experiments"].items():
        sections += [f'<section class="panel" id="{name}"><p class="eyebrow">{name} · FROZEN DECISION</p>'
                     f'<h2>{cell(result["decision"])}</h2><p>{cell(result["reason"])}</p>']
        sections.append(table(["Denominator / count", "Value"], [
            ("Frozen target (not an observed denominator)", result["target_denominator"]),
            ("Original declared roster", result["roster_denominator"]),
            ("Actual cohort denominator", result["actual_denominator"]),
            ("All invitations", result["invitations"]),
            ("Observation rows, including invalid rows", result["observation_rows"]),
            ("Eligible actual observations", result["eligible_actual"]),
            ("Eligible simulated observations (never demand evidence)", result["eligible_simulated"]),
            ("Excluded rows", len(result["excluded"])),
            ("Missing original participants", len(result["missing_participants"])),
            ("Qualifying actual written responses", result["qualifying_written_responses"]),
            ("Qualifying actual gate successes", result["qualifying_successes"]),
        ]))
        sections.append('<h3>Keep the recipes visible</h3>' + table(
            ["Recipe", "Original roster", "Eligible actual", "Actual gate successes"],
            [(recipe, values["roster"], values["eligible_actual"], values["qualifying_successes"])
             for recipe, values in result["by_recipe"].items()]))
        sections.append('<h3>Distinct actual outcomes</h3>' + table(
            ["Outcome", "True observations", "Known values", "Original denominator", "Missing values", "Complete fraction"],
            [(label, values["count"], values["observed"], values["denominator"], values["missing"], values["fraction"])
             for field, label in METRICS.items() for values in [result["metrics"][field]]]))
        support = result["support_minutes"]
        sections.append('<h3>Support includes failed attempts</h3>' + table(
            ["Complete support minutes", "Known partial minutes", "Participants with unknown support"],
            [(support["total"], support["known_partial"], support["missing"])]))
        sections.append('<p class="fine">An undefined total remains undefined. Partial support is not the full cost. '
                        'Later E3/E5/E6 gates are not evaluated by these descriptive fields.</p>')
        problems = result["integrity_errors"] + result["required_evidence"]
        sections.append('<h3>Missing prerequisites / integrity</h3><ul>' +
                        ''.join(f'<li>{cell(item)}</li>' for item in problems) + '</ul>')
        if result["missing_participants"]:
            sections.append(table(["Missing participant", "Task", "Recipe"],
                                  [(p["participant_id"], p["task_id"], p["recipe"]) for p in result["missing_participants"]]))
        if result["excluded"]:
            sections.append(table(["Excluded participant", "Reasons"],
                                  [(row["participant_id"], '; '.join(row["reasons"])) for row in result["excluded"]]))
        sections.append('<h3>Every submitted row, including simulations and dropouts</h3>' + table(
            ["Participant / task", "Recipe", "Kind", "Actual eligible", "Dropout", "Active seconds", "Baseline seconds", "Assistance", "Support minutes", "Price response", "Exclusion reasons"],
            [(f'{row["participant_id"]} / {row["task_id"]}', row["recipe"], row["kind"], row["eligible_actual"],
              row["dropped_out"], row["active_seconds"], row["baseline_active_seconds"], row["required_assistance"],
              row["support_minutes"], row["price_response"], '; '.join(row["errors"])) for row in result["rows"]]))
        sections.append('</section>')
    offer = report["example_offer_arithmetic"]
    sections.append('<section class="card"><h2>Proposed price arithmetic; purchase unavailable</h2>'
                    f'<p>Three maintaining humans × $6/month = ${cell(offer["monthly_usd"])}/month '
                    f'(${cell(offer["annual_usd"])}/year). Personal launch: $12/year for about 50 paying signups, '
                    'with early users grandfathered. Existing entitlement changes: 0.</p>'
                    '<button type="button" disabled>Signup and payment unavailable</button></section>')
    sections.append('<section><h2>Frozen kill rules</h2><p>E1: ten qualifying written responses by day 14 or 50 recruitment minutes; '
                    'at least six recurring cases, three per recipe, each at least twice in the last month. '
                    'Below the threshold at closure kills the two-recipe recruitment hypothesis.</p>'
                    '<p>E2: four of the original six, three assigned per recipe, must complete the useful task in ≤300 active seconds, '
                    '≤half the strongest viable baseline time, and choose tunn next. Below the threshold at closure kills setup-speed '
                    'differentiation. Missing real prerequisites remain incomplete; any actual unsafe grant stops hosted testing.</p></section>')
    return '\n'.join(sections)

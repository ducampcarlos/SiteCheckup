# Working with clients and developers

Hosting, migrations and security work sits between people who care about the business (clients, owners) and people who change the system (developers, sysadmins). Most delays come from translation failures, not from technical difficulty. This playbook collects the templates and habits that reduce them. All scenarios are invented.

## Principles

1. **Say what it means, then how it works.** Clients decide on impact, cost and time. Developers need mechanics. Lead with the part your reader decides on.
2. **Be specific about the next step and the owner.** "We should look at security" is not a plan. "Maria's team enables 2FA for all admin accounts by Friday" is.
3. **Write it down.** Decisions made in calls are confirmed in writing the same day.
4. **Bad news early, with options.** Never arrive with a problem alone; arrive with two or three ways forward and a recommendation.
5. **No blame.** The question is "what let this happen and how do we stop it recurring", never "who".

## Translating technical risk for non-technical clients

Structure: **what we found -> what could happen -> how likely and how bad -> what we recommend -> what it costs -> what happens if we wait.**

| Technical finding | Plain-language version |
| --- | --- |
| "No HSTS and no HTTP->HTTPS redirect" | "Visitors who type the address without `https` can be tricked on public Wi-Fi into a fake or unprotected version of the site. Fix: one setting, about an hour, no visible change for visitors." |
| "`/backup.sql` is publicly downloadable" | "A copy of the customer database was sitting in a public folder. Anyone who guessed the name could download it. We removed it today; we are changing the passwords it contained and we need to decide whether customers must be notified." |
| "WordPress user enumeration via REST" | "Anyone can see the login names of everyone who can edit the site. That is half of what an attacker needs to guess a password. Fix: hide the list and turn on two-step login." |
| "Missing CSP" | "If an attacker ever manages to slip a malicious script into a page, the browser has no instruction to stop it. We add that instruction in stages so nothing on the site breaks." |
| "301 redirect chain, 4 hops" | "Old links take four jumps to arrive at the right page. Visitors and Google both lose patience. We can make it one jump." |
| "`noindex` on production after migration" | "A leftover setting from testing is telling Google not to show the new site in results. Until we remove it, traffic from search will drop. This is the first thing we fix." |

Tips: avoid acronyms on first use; quantify when you can ("about 4,000 customer records", "1 hour of work") and say when you cannot; separate *severity* from *urgency*; never use fear as a lever, a calm, concrete description is more persuasive and more honest.

## Writing a clear ticket

A developer should be able to start work without a meeting. Template:

```markdown
**Title:** [verb] [what] [where]   e.g. "Block public access to /xmlrpc.php on shop.example.test"

**Why:** One or two sentences on the risk or business need. Link to the report or finding ID.

**Where:** Environment(s), URL(s), host(s), repository, component.

**Current behaviour:** What happens now, with evidence (response, header, screenshot, check ID).

**Expected behaviour / acceptance criteria:**
- [ ] Observable, testable statement ("GET /xmlrpc.php returns 403")
- [ ] ...

**Suggested approach (optional):** A starting point, not a mandate.

**Out of scope:** What this ticket deliberately does not cover.

**Verification:** Exactly how the reviewer will check it, e.g.
`sitecheckup audit https://staging.example.test --i-have-permission --skip wp-login-exposed`
and that `wp-xmlrpc` is now passing.

**Owner / due date / priority:** ...
**Rollback:** How to undo it if it breaks something.
```

Good habits: one concern per ticket (but group findings that share a root cause); acceptance criteria that can be verified by someone other than the author; link evidence rather than pasting walls of output; state constraints (change window, who must approve, dependencies).

### Example (invented)

> **Block public access to `/xmlrpc.php` on shop.example.test**
> **Why:** `xmlrpc.php` allows high-volume password guessing; the site does not use any XML-RPC integration. Audit check `wp-xmlrpc`, medium.
> **Current:** `GET /xmlrpc.php` -> `405 XML-RPC server accepts POST requests only`.
> **Acceptance:** `GET` and `POST` to `/xmlrpc.php` return 403 on staging and production; the contact form and the checkout still work; `sitecheckup audit` shows `wp-xmlrpc` passing.
> **Approach:** deny rule in the nginx server block for `= /xmlrpc.php`.
> **Rollback:** remove the rule and reload nginx.

## Status-update templates

Send them on a rhythm and keep them short. People read the first three lines.

### Weekly status (client)

```
Subject: [Project] status, week of 2026-03-02: on track / at risk / blocked

Summary (2-3 lines): where we are in plain language, and one sentence on risk.

Done this week
- ...
Next week
- ...
Decisions or input needed from you (with due dates)
- ...
Risks and how we are handling them
- ...
```

### Incident or urgent finding

```
Subject: [Project] [Urgent] <what happened in a few words>

What happened: one or two sentences, plain language.
Impact: who or what is affected, and what is not.
What we have done so far: actions with times.
What we are doing next: actions, owners, expected times.
What we need from you: decisions or access, if any.
Next update: at HH:MM (even if there is nothing new).
```

### Migration cutover

```
Subject: [Project] migration cutover, <date>

Window: start, expected end, rollback decision point.
Impact during the window: what will and will not work.
Who is on call: names and how to reach them.
Success criteria: checks we will run (compare report: zero blocking issues, audit grade not lower than baseline).
Rollback: the trigger and the owner.
```

### Post-migration summary

```
Subject: [Project] migration complete, summary

Result: complete / complete with follow-ups.
Validated: N URLs compared; blocking X, warnings Y (all listed, owners assigned).
Follow-ups: items, owners, dates.
Monitoring: what we watch for the next 2-4 weeks.
Attachments: compare report, audit report.
```

## Handling common friction

| Situation | What to do |
| --- | --- |
| Client wants a deadline you cannot meet | Offer options: reduce scope, add people, move date. Show the trade-off; do not just say no. |
| Developer says "that's not a real vulnerability" | Ask for the reasoning, reproduce together, agree on what evidence would change either view. Write down the outcome. |
| Two stakeholders disagree on priority | Put the decision in front of the one who owns the budget or risk, with a recommendation and the consequences of each option. |
| Silent stakeholder | Send a specific question with a default ("If I hear nothing by Thursday I will proceed with option B"). |
| A change broke something | Restore service first, communicate, then analyse. Share the analysis in blameless form: timeline, cause, contributing factors, fixes, prevention. |
| Scope creep in a migration | Capture the request in the backlog, estimate it, and let the owner decide whether it displaces something. |

## Checklist before you hit send

- [ ] Does the first paragraph say what you need from the reader?
- [ ] Is there one clear owner and date for every action?
- [ ] Could someone who missed the call act on this message?
- [ ] Have you separated facts from opinions and flagged assumptions?
- [ ] Is anything sensitive (credentials, internal hostnames, personal data) included that should not be?

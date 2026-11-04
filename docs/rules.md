# Detection rules

32 rules, rule format 1.0.0. Generated from `backend/mizar/rules/*.yaml` by `python -m mizar.detection.rules_docs`; do not edit by hand. Severity and confidence below are base values; each finding records the modifiers that changed them.

| ID | Version | Type | ATT&CK | Severity | Confidence | Evidence | Title |
|---|---|---|---|---|---|---|---|
| AUTH-001 | 1.0.0 | threshold | T1110.001 | medium | medium | direct | Possible SSH brute force from {source_ip} against {hostname} |
| AUTH-002 | 1.0.0 | threshold | T1110.003 | medium | medium | direct | Possible password spraying from {source_ip} ({distinct.username} accounts) |
| AUTH-003 | 1.0.0 | sequence | T1110, T1078 | high | medium | direct | Successful logon for {username} from {source_ip} after repeated failures |
| AUTH-004 | 1.0.0 | threshold | T1110 | medium | medium | direct | Windows logon failure burst from {source_ip} on {hostname} |
| AUTH-005 | 1.0.0 | match | T1110 | low | medium | direct | Account lockout for {username} |
| AUTH-006 | 1.0.0 | threshold | T1110 | low | medium | direct | Logon attempts for non-existent accounts from {source_ip} |
| AUTH-007 | 1.0.0 | first_seen | T1078 | low | low | inferred | Logon for {username} from a source first seen after the baseline ({source_ip}) |
| AUTH-008 | 1.0.0 | match | T1021.001 | medium | medium | direct | Remote interactive logon for {username} from public address {source_ip} |
| AUTH-009 | 1.0.0 | match | T1078, T1021 | low | low | direct | Explicit credentials used by {username} to reach {target_server} |
| CORR-001 | 1.0.0 | correlation | T1190, T1078 | high | medium | corroborated | Web attack activity from {source_ip} followed by a successful logon from the same address |
| CORR-002 | 1.0.0 | correlation | T1136, T1098 | high | medium | corroborated | Account or privilege changes on {hostname} soon after a suspicious logon |
| DEF-001 | 1.0.0 | match | T1070.001 | high | high | direct | Event log cleared on {hostname} |
| NET-001 | 1.0.0 | threshold | T1046 | medium | medium | direct | Possible port scan from {source_ip} ({distinct.destination_port} ports) |
| NET-002 | 1.0.0 | threshold | T1046 | low | medium | direct | Burst of denied connections from {source_ip} |
| NET-003 | 1.0.0 | match | T1046 | informational | medium | direct | Zeek notice {event_code} |
| PERS-001 | 1.0.0 | match | T1136.001 | medium | medium | direct | Local account {username} created on {hostname} |
| PERS-002 | 1.0.0 | match | T1543.003 | medium | medium | direct | Service {service_name} installed on {hostname} |
| PERS-003 | 1.0.0 | match | T1053.005 | medium | medium | direct | Scheduled task {task_name} created on {hostname} |
| PERS-004 | 1.0.0 | match | T1053.003 | low | medium | direct | Crontab of {crontab_of} changed by {username} on {hostname} |
| PERS-005 | 1.0.0 | match | T1098.004 | medium | low | direct | SSH authorized_keys modified on {hostname} |
| PRIV-001 | 1.0.0 | match | T1548.003 | medium | medium | direct | sudo attempted by {username}, who is not in sudoers, on {hostname} |
| PRIV-002 | 1.0.0 | threshold | T1548.003 | low | low | direct | Repeated sudo authentication failures for {username} on {hostname} |
| PRIV-003 | 1.0.0 | match | T1098 | high | medium | direct | {username} added to privileged group {group\|group_name} on {hostname} |
| PRIV-004 | 1.0.0 | first_seen | T1078.002 | low | low | inferred | Special privileges assigned to {username} on {hostname} after the baseline |
| PRIV-005 | 1.0.0 | match | T1003.008 | medium | low | direct | Credential file access by {process_name} on {hostname} |
| WEB-001 | 1.0.0 | match | T1595.002 | low | medium | direct | Attack or scanning tool User-Agent from {source_ip} |
| WEB-002 | 1.0.0 | match | T1190 | medium | low | direct | SQL injection patterns in requests from {source_ip} |
| WEB-003 | 1.0.0 | match | T1190 | medium | medium | direct | Path traversal or file inclusion patterns from {source_ip} |
| WEB-004 | 1.0.0 | match | T1190 | low | low | direct | Cross-site scripting patterns in requests from {source_ip} |
| WEB-005 | 1.0.0 | match | T1505.003 | high | medium | direct | Possible web shell interaction from {source_ip} |
| WEB-006 | 1.0.0 | threshold | T1595.003 | low | medium | direct | Burst of 404 responses for {source_ip} |
| WEB-007 | 1.0.0 | match | T1190 | high | low | circumstantial | Attack pattern requests answered with HTTP 200 for {source_ip} |

## AUTH-001 — Possible SSH brute force from {source_ip} against {hostname}

{count} failed SSH authentication attempts from {source_ip} to {hostname} were recorded within {params.window} windows, involving {distinct.username} account name(s).

Parameters:

- `min_failures` (integer, default `20`): Failed attempts needed within the window
- `window` (duration, default `10m`): Sliding time window

Alternative explanations:

- Automation or monitoring configured with an outdated password.
- An authorized vulnerability scan or penetration test.
- Several users sharing one NAT or proxy address.

Verification steps:

- Check whether any logon from {source_ip} succeeded afterwards (see AUTH-003 findings).
- Ask the network owner whether {source_ip} is an authorized scanner or automation host.
- Review firewall and other hosts' logs for the same address.

## AUTH-002 — Possible password spraying from {source_ip} ({distinct.username} accounts)

Failed logons for {distinct.username} different accounts came from {source_ip} within {params.window} windows ({count} attempts in total).

Parameters:

- `min_accounts` (integer, default `10`): Distinct account names needed within the window
- `window` (duration, default `30m`): Sliding time window

Alternative explanations:

- A shared terminal server or proxy where many users mistype passwords.
- An identity system or application synchronizing with an outdated credential list.
- An authorized security assessment.

Verification steps:

- Check for successful logons from {source_ip} in the same period (AUTH-003).
- Identify what system owns {source_ip} and whether it legitimately authenticates many users.
- Look for account lockouts (AUTH-005) for the targeted accounts.

## AUTH-003 — Successful logon for {username} from {source_ip} after repeated failures

A successful logon for {username} on {hostname} from {source_ip} was recorded after {failures_count} failed attempts from the same address within {params.window}.

Parameters:

- `min_failures` (integer, default `5`): Failed attempts that must precede the success
- `window` (duration, default `1h`): Maximum time from the counted failures to the success

Alternative explanations:

- The account owner mistyped the password several times, then entered it correctly.
- A script or service retried with an old password before its configuration was fixed.

Verification steps:

- Ask the owner of {username} whether they logged on from {source_ip} at {last}.
- Review what the session did after the logon (processes, sudo, new accounts, file changes).
- Reset the credential if the logon cannot be explained, and check other hosts for the same account.

## AUTH-004 — Windows logon failure burst from {source_ip} on {hostname}

{count} failed Windows logons (event 4625) from {source_ip} were recorded on {hostname} within {params.window} windows, for {distinct.username} account name(s).

Parameters:

- `min_failures` (integer, default `10`): Failed logons needed within the window
- `window` (duration, default `5m`): Sliding time window

Alternative explanations:

- A service or scheduled task running with an outdated password.
- Mapped drives or cached credentials retrying after a password change.
- An authorized security test.

Verification steps:

- Check the failure sub-status codes (wrong password vs unknown user) in the evidence.
- Look for a successful logon from {source_ip} after the burst (AUTH-003).
- Identify the process or workstation named in the events.

## AUTH-005 — Account lockout for {username}

The account {username} was locked out {event_count} time(s) on {hostname}.

Alternative explanations:

- The user forgot or mistyped a recently changed password.
- A device or service still uses the old password.

Verification steps:

- Find the failed logons that preceded the lockout and their source.
- Ask the account owner whether they were locked out.

## AUTH-006 — Logon attempts for non-existent accounts from {source_ip}

{count} logon attempts for account names that do not exist came from {source_ip} ({distinct.username} different names) within {params.window} windows.

Parameters:

- `min_attempts` (integer, default `5`): Attempts needed within the window
- `window` (duration, default `10m`): Sliding time window

Alternative explanations:

- A client configured with a wrong or removed account name.
- An inventory or monitoring tool probing with default names.

Verification steps:

- Review which account names were tried (top values in the evidence).
- Check whether {source_ip} also tried existing accounts (AUTH-001, AUTH-002).

## AUTH-007 — Logon for {username} from a source first seen after the baseline ({source_ip})

A successful logon for {username} from {source_ip} was first recorded after the first {params.baseline} of this case's logon data, with no earlier logon from that address.

Parameters:

- `baseline` (duration, default `24h`): Initial period of the data treated as normal

Alternative explanations:

- The user started working from a new location, VPN or device.
- The case data starts too late to include earlier logons from this address.

Verification steps:

- Ask the account owner whether the logon from {source_ip} was theirs.
- Check what the session did after the logon.

## AUTH-008 — Remote interactive logon for {username} from public address {source_ip}

A Remote Desktop (logon type 10) logon for {username} on {hostname} came from {source_ip}, which is not a private address.

Alternative explanations:

- An administrator connecting from home or a hosted jump server.
- A managed service provider with an approved public address.

Verification steps:

- Confirm with the account owner and network team that {source_ip} is expected.
- Check whether failed logons from {source_ip} preceded this logon (AUTH-003).
- Review firewall rules exposing port 3389.

## AUTH-009 — Explicit credentials used by {username} to reach {target_server}

Logons with explicitly supplied credentials (event 4648) for {username} targeting {target_server} were recorded {event_count} time(s) on {hostname}.

Alternative explanations:

- An administrator using runas, mapped drives or remote management tools.
- A scheduled task or service configured with an explicit account.

Verification steps:

- Identify the process named in the events and whether it is an expected admin tool.
- Check logons on {target_server} at the same time for {username}.

## CORR-001 — Web attack activity from {source_ip} followed by a successful logon from the same address

{source_ip} sent web attack requests and then logged on successfully to a system within {params.window}.

Parameters:

- `window` (duration, default `24h`): Maximum time from the end of the web activity to the logon

Alternative explanations:

- Several users share {source_ip} behind NAT or a proxy.
- An authorized penetration test using one address for all activity.

Verification steps:

- Check the web findings and the logon in the chain for timing and accounts.
- Ask the owner of {username} whether the logon was theirs.
- Review the session that followed the logon.

## CORR-002 — Account or privilege changes on {hostname} soon after a suspicious logon

A suspicious logon on {hostname} was followed within {params.window} by account, service, task or privilege changes on the same host.

Parameters:

- `window` (duration, default `2h`): Maximum time from the logon finding to the change

Alternative explanations:

- An administrator logged on and made planned changes; the logon finding may itself be benign.
- Unrelated activity on a busy host that happens to fall in the same window.

Verification steps:

- Check whether the session of the logon finding made the changes (logon/session IDs in the evidence).
- Look for change records approving the account, group, service or task changes.
- Treat the host as untrusted until the chain is explained.

## DEF-001 — Event log cleared on {hostname}

An event log on {hostname} was cleared at {first} by {username}.

Alternative explanations:

- An administrator clearing a full log during maintenance.
- Reimaging or test procedures.

Verification steps:

- Ask {username} and the system owner whether the log was cleared intentionally.
- Look for forwarded copies of the log (SIEM, Windows Event Forwarding) covering the gap.
- Review the activity of {username} immediately before {first}.

## NET-001 — Possible port scan from {source_ip} ({distinct.destination_port} ports)

{source_ip} attempted connections to {distinct.destination_port} different destination ports within {params.window} windows.

Parameters:

- `min_ports` (integer, default `50`): Distinct destination ports needed within the window
- `window` (duration, default `5m`): Sliding time window

Alternative explanations:

- An authorized network scanner or asset inventory tool.
- Peer-to-peer or VoIP software using many ports.

Verification steps:

- Identify the owner of {source_ip} and whether scanning is authorized.
- Check whether any scanned port was open and later contacted again by the same source.

## NET-002 — Burst of denied connections from {source_ip}

{count} connections from {source_ip} were denied by a firewall within {params.window} windows.

Parameters:

- `min_denied` (integer, default `100`): Denied connections needed within the window
- `window` (duration, default `10m`): Sliding time window

Alternative explanations:

- A misconfigured client retrying a blocked service.
- Background internet scanning, which is constant on public addresses.

Verification steps:

- Check which destination ports were targeted (top values in the evidence).
- Look for allowed connections from the same source.

## NET-003 — Zeek notice {event_code}

Zeek raised the notice {event_code} {event_count} time(s) for {source_ip}.

Alternative explanations:

- The notice may be tuned for a different environment and fire on normal traffic.

Verification steps:

- Read the Zeek script documentation for {event_code} and the connection it refers to.

## PERS-001 — Local account {username} created on {hostname}

The account {username} was created on {hostname} at {first}.

Alternative explanations:

- Routine onboarding or provisioning of a service account.
- Package installation creating a system user.

Verification steps:

- Find who created the account and whether a request or ticket exists.
- Check the account's group memberships and logons after {first}.

## PERS-002 — Service {service_name} installed on {hostname}

A new service {service_name} ({image_path\|service_file}) was installed on {hostname} at {first}.

Alternative explanations:

- Installation or update of legitimate software.
- Remote administration tools that install a temporary service.

Verification steps:

- Check the binary path, its signature and hash.
- Identify which session or process installed the service.

## PERS-003 — Scheduled task {task_name} created on {hostname}

The scheduled task {task_name} was created on {hostname} by {username} at {first}.

Alternative explanations:

- Software installers and updaters registering maintenance tasks.
- An administrator scheduling a job.

Verification steps:

- Review the task's action (the command it runs) in the event data.
- Check who created it and whether the command is a known, signed program.

## PERS-004 — Crontab of {crontab_of} changed by {username} on {hostname}

{username} replaced or deleted the crontab of {crontab_of} on {hostname} ({event_count} time(s)).

Alternative explanations:

- An administrator editing scheduled jobs.
- Configuration management deploying cron entries.

Verification steps:

- Inspect the current crontab of {crontab_of} on {hostname} and its backup copies.
- Check which session made the change at {first}.

## PERS-005 — SSH authorized_keys modified on {hostname}

The audit log recorded {event_count} access(es) to SSH authorized_keys files ({paths}) on {hostname} by {process_name}.

Alternative explanations:

- A user adding their own new key.
- Configuration management distributing keys.

Verification steps:

- Compare the current authorized_keys files with a known-good copy.
- Check the syscall in the evidence (open for writing vs reading).

## PRIV-001 — sudo attempted by {username}, who is not in sudoers, on {hostname}

{username} tried to run commands with sudo {event_count} time(s) on {hostname} without being allowed to.

Alternative explanations:

- A user who expected sudo rights they were never granted.
- A script copied from another system that calls sudo.

Verification steps:

- Review the commands that were attempted (extra.command in the evidence).
- Ask the account owner about the attempts and check how they logged on.

## PRIV-002 — Repeated sudo authentication failures for {username} on {hostname}

{count} sudo authentication failures for {username} on {hostname} within {params.window} windows.

Parameters:

- `min_failures` (integer, default `3`): Failures needed within the window
- `window` (duration, default `10m`): Sliding time window

Alternative explanations:

- The user mistyped their password repeatedly.
- A script feeding the wrong password to sudo.

Verification steps:

- Check whether a successful sudo followed the failures.
- Ask the account owner about the attempts.

## PRIV-003 — {username} added to privileged group {group\|group_name} on {hostname}

The account {username} was added to the privileged group {group\|group_name} on {hostname} at {first}.

Alternative explanations:

- A planned change by an administrator (check the change record).
- Automated provisioning of a new administrator account.

Verification steps:

- Find who made the change ({actor} if recorded, or the session active at {first}).
- Check for a change ticket approving the addition.
- Review the account's activity after the change.

## PRIV-004 — Special privileges assigned to {username} on {hostname} after the baseline

{username} received special privileges at logon (event 4672) on {hostname}, first after the first {params.baseline} of this case's data.

Parameters:

- `baseline` (duration, default `24h`): Initial period of the data treated as normal

Alternative explanations:

- An administrator who simply had not logged on earlier in the data.
- A newly created or newly authorized admin account.

Verification steps:

- Check whether {username} is an expected administrator of {hostname}.
- Review group changes for {username} before {first} (PRIV-003).

## PRIV-005 — Credential file access by {process_name} on {hostname}

The audit log recorded {event_count} access(es) to credential files ({paths}) by {process_name} on {hostname}.

Alternative explanations:

- Login, sudo, passwd or PAM utilities reading the files as part of normal operation.
- Configuration management or backup software.

Verification steps:

- Check the user and session that ran {process_name} (audit session ID in the evidence).
- Look for the file contents being copied or transferred afterwards.

## WEB-001 — Attack or scanning tool User-Agent from {source_ip}

{event_count} web requests from {source_ip} identified themselves as a known scanning or attack tool.

Alternative explanations:

- An authorized vulnerability scan or penetration test.
- A researcher or monitoring service using the tool openly.

Verification steps:

- Ask whether a security test from {source_ip} was scheduled.
- Check which requests received 2xx responses (WEB-007).

## WEB-002 — SQL injection patterns in requests from {source_ip}

{event_count} requests from {source_ip} contained SQL injection patterns in the URL.

Alternative explanations:

- An authorized application security test.
- Users or search terms that happen to contain SQL keywords.

Verification steps:

- Check the response codes and sizes of the matching requests (unusual sizes may mean data returned).
- Review application and database logs for errors or queries at the same times.

## WEB-003 — Path traversal or file inclusion patterns from {source_ip}

{event_count} requests from {source_ip} tried to reach files outside the web root.

Alternative explanations:

- An authorized security scan.
- A badly built client constructing relative paths.

Verification steps:

- Check which matching requests returned 200 and their response sizes (WEB-007).
- Test whether the targeted parameter actually serves local files.

## WEB-004 — Cross-site scripting patterns in requests from {source_ip}

{event_count} requests from {source_ip} contained script or event-handler markup in the URL.

Alternative explanations:

- An authorized scan or a developer testing input handling.
- Links copied from pages that contain such markup.

Verification steps:

- Check whether the application reflects the parameter unescaped in its response.

## WEB-005 — Possible web shell interaction from {source_ip}

{event_count} successful requests from {source_ip} called a server-side script with command-like parameters.

Alternative explanations:

- A legitimate administrative script that takes a "cmd" parameter.
- A scanner probing for known shells against pages that return 200 for every URL.

Verification steps:

- Inspect the script file on the server and compare it with the deployed application.
- Check the response sizes and process activity on the server at {first}–{last}.
- Look for how the script was uploaded (POST requests to the same path).

## WEB-006 — Burst of 404 responses for {source_ip}

{count} requests from {source_ip} received 404 Not Found within {params.window} windows.

Parameters:

- `min_requests` (integer, default `50`): 404 responses needed within the window
- `window` (duration, default `5m`): Sliding time window

Alternative explanations:

- A broken link checker or misconfigured client.
- An authorized scanner.

Verification steps:

- Review which paths were requested and whether any returned 200 afterwards.

## WEB-007 — Attack pattern requests answered with HTTP 200 for {source_ip}

{event_count} requests from {source_ip} with SQL injection or traversal patterns received HTTP 200.

Alternative explanations:

- The application returned a normal page and ignored the injected input.
- A custom error page served with status 200.

Verification steps:

- Compare the response sizes with normal responses for the same paths.
- Reproduce the request against a test copy of the application.
- Review application and database logs at the same times.

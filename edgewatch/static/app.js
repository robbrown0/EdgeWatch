"use strict";

const state = {
  snapshot: null,
  history: [],
  historyMinutes: 60,
  eventSource: null,
  lastLiveAt: 0,
  chartFrame: null,
  mapMode: "world",
  flowScope: "active",
  flowKind: "public",
  mapRenderToken: 0,
  liveTrafficSamples: [],
};

const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";

function node(tag, className = "", text = null) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== null && text !== undefined) element.textContent = String(text);
  return element;
}

function svgNode(tag, attributes = {}) {
  const element = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, String(value));
  return element;
}

function clear(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function number(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function formatBytes(value, decimals = 1) {
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let size = Math.max(0, number(value));
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  const shown = unit === 0 ? Math.round(size) : size.toFixed(decimals);
  return `${shown} ${units[unit]}`;
}

function formatRate(value) {
  return `${formatBytes(value)}/s`;
}

function formatDuration(seconds) {
  let remaining = Math.max(0, number(seconds));
  const days = Math.floor(remaining / 86400);
  remaining %= 86400;
  const hours = Math.floor(remaining / 3600);
  remaining %= 3600;
  const minutes = Math.floor(remaining / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function ageLabel(seconds) {
  if (seconds === null || seconds === undefined) return "Never";
  const value = number(seconds);
  if (value < 60) return `${Math.round(value)}s ago`;
  if (value < 3600) return `${Math.round(value / 60)}m ago`;
  return `${(value / 3600).toFixed(1)}h ago`;
}

function timeLabel(epoch) {
  if (!epoch) return "Unknown";
  return new Date(number(epoch) * 1000).toLocaleString([], {
    month: "short", day: "numeric", hour: "numeric", minute: "2-digit",
  });
}

function riskColor(score) {
  if (score < 10) return "#34d399";
  if (score < 30) return "#fbbf24";
  if (score < 60) return "#fb923c";
  return "#fb7185";
}

function showToast(message) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 2400);
}

function setMeter(id, value) {
  $(id).style.width = `${Math.max(0, Math.min(100, number(value)))}%`;
}

function setStatusBadge(element, text, stateName = "good") {
  element.textContent = text;
  element.classList.remove("good", "warn", "bad");
  element.classList.add(stateName);
}

// EdgeWatch clickable security findings

function securityFindingBoolean(value) {
  if (value === true) return "Yes";
  if (value === false) return "No";

  return value;
}

function securityFindingSnapshotTime(snapshot) {
  const value = snapshot?.generated_at;

  if (!value) {
    return "Current collector snapshot";
  }

  const parsed = new Date(value);

  if (Number.isNaN(parsed.getTime())) {
    return String(value);
  }

  return parsed.toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "medium",
  });
}

function securityFindingEvidence(
  insight,
  snapshot
) {
  const security = snapshot?.security || {};
  const sshd = security.sshd || {};
  const firewall = security.firewall || {};
  const automatic =
    security.automatic_updates || {};
  const journal =
    security.service_journal || {};
  const linode =
    snapshot?.linode_firewall || {};

  const fingerprint =
    String(insight?.fingerprint || "");

  const rows = [];

  const add = (label, value) => {
    if (
      value === undefined ||
      value === null ||
      value === ""
    ) {
      return;
    }

    rows.push([
      label,
      securityFindingBoolean(value),
    ]);
  };

  if (
    fingerprint.startsWith("ssh-") ||
    fingerprint === "sshd-audit-unavailable"
  ) {
    add(
      "Audit available",
      sshd.available
    );

    add(
      "PasswordAuthentication",
      sshd.password_authentication
    );

    add(
      "PermitRootLogin",
      sshd.permit_root_login
    );

    add(
      "PubkeyAuthentication",
      sshd.pubkey_authentication
    );

    add(
      "MaxAuthTries",
      sshd.max_auth_tries
    );

    add(
      "AllowUsers",
      sshd.allow_users || "Not restricted"
    );

    add(
      "AllowGroups",
      sshd.allow_groups || "Not restricted"
    );

    add(
      "Audit detail",
      sshd.detail
    );
  }

  if (
    fingerprint ===
    "systemd-failed-units"
  ) {
    const failedUnits =
      Array.isArray(security.failed_units)
        ? security.failed_units
        : [];

    add(
      "Failed unit count",
      failedUnits.length
    );

    add(
      "Failed units",
      failedUnits.length
        ? failedUnits.join(", ")
        : "None currently reported"
    );
  }

  if (
    fingerprint === "pending-updates"
  ) {
    add(
      "Pending packages",
      number(security.pending_updates)
    );

    add(
      "Upgrade timer enabled",
      automatic.enabled
    );

    add(
      "Upgrade timer active",
      automatic.active
    );

    add(
      "Automatic update health",
      automatic.ok
    );

    add(
      "Reboot required",
      security.reboot_required
    );

    add(
      "Maintenance data age",
      security.maintenance_age_seconds !==
        undefined
        ? `${number(
            security.maintenance_age_seconds
          ).toFixed(0)} seconds`
        : ""
    );
  }

  if (
    fingerprint ===
    "service-journal-warnings"
  ) {
    add(
      "Warning count",
      number(journal.warning_count)
    );

    add(
      "Journal available",
      journal.available
    );

    const samples =
      Array.isArray(journal.samples)
        ? journal.samples
        : [];

    samples.forEach((sample, index) => {
      if (
        sample &&
        typeof sample === "object"
      ) {
        const value = [
          sample.service,
          sample.timestamp,
          sample.message,
        ]
          .filter(Boolean)
          .join(" · ");

        add(
          `Journal entry ${index + 1}`,
          value
        );
      } else {
        add(
          `Journal entry ${index + 1}`,
          sample
        );
      }
    });
  }

  if (
    fingerprint === "ufw-inactive"
  ) {
    add(
      "Firewall available",
      firewall.available
    );

    add(
      "Firewall active",
      firewall.active
    );

    add(
      "Firewall detail",
      firewall.detail
    );
  }

  if (
    fingerprint ===
    "unexpected-public-listeners"
  ) {
    const listeners =
      Array.isArray(
        security.unexpected_listeners
      )
        ? security.unexpected_listeners
        : [];

    add(
      "Unexpected listener count",
      listeners.length
    );

    listeners.forEach(
      (listener, index) => {
        if (
          listener &&
          typeof listener === "object"
        ) {
          const endpoint = [
            listener.protocol,
            listener.port,
          ]
            .filter(
              (value) =>
                value !== undefined &&
                value !== null
            )
            .join("/");

          const owner =
            listener.process ||
            listener.program ||
            listener.command ||
            "";

          add(
            `Listener ${index + 1}`,
            [endpoint, owner]
              .filter(Boolean)
              .join(" · ")
          );
        }
      }
    );
  }

  if (
    fingerprint.startsWith(
      "linode-firewall"
    )
  ) {
    add(
      "Configured",
      linode.configured
    );

    add(
      "Enabled",
      linode.enabled
    );

    add(
      "Attached",
      linode.attached
    );

    add(
      "Status",
      linode.status
    );

    add(
      "Inbound policy",
      linode.inbound_policy
    );

    add(
      "Outbound policy",
      linode.outbound_policy
    );

    add(
      "Firewall label",
      linode.label
    );
  }

  if (
    fingerprint ===
    "time-not-synchronized"
  ) {
    const sync = security.time_sync || {};

    add(
      "NTP available",
      sync.available
    );

    add(
      "Synchronized",
      sync.synchronized
    );

    add(
      "Time service detail",
      sync.detail
    );
  }

  if (
    fingerprint === "apparmor-inactive"
  ) {
    const apparmor =
      security.apparmor || {};

    add(
      "AppArmor available",
      apparmor.available
    );

    add(
      "AppArmor active",
      apparmor.active
    );

    add(
      "Loaded profiles",
      apparmor.profiles
    );
  }

  if (
    fingerprint.includes("fail2ban")
  ) {
    const fail2ban =
      security.fail2ban || {};

    add(
      "Installed",
      fail2ban.installed
    );

    add(
      "Active",
      fail2ban.active
    );

    add(
      "Jails",
      Array.isArray(fail2ban.jails)
        ? fail2ban.jails.join(", ")
        : fail2ban.jails
    );
  }

  if (
    fingerprint ===
    "kernel-network-hardening"
  ) {
    const controls =
      Array.isArray(
        security.kernel?.controls
      )
        ? security.kernel.controls
        : [];

    controls.forEach((control) => {
      if (!control?.ok) {
        add(
          control.name || "Kernel control",
          control.value
        );
      }
    });
  }

  if (
    fingerprint.includes("geoip")
  ) {
    const geoip = snapshot?.geoip || {};

    add(
      "City database available",
      geoip.city_available
    );

    add(
      "ASN database available",
      geoip.asn_available
    );

    add(
      "Database age",
      geoip.age_days !== undefined
        ? `${geoip.age_days} days`
        : ""
    );

    add(
      "GeoIP detail",
      geoip.detail
    );
  }

  if (!rows.length) {
    add(
      "Collector evidence",
      insight?.detail ||
        "No additional structured evidence was supplied."
    );
  }

  return rows;
}

// EdgeWatch security finding commands

function securityShellQuote(value) {
  return (
    "'" +
    String(value || "")
      .replace(/'/g, "'\\''") +
    "'"
  );
}

function securityFailedUnitNames(snapshot) {
  const values =
    Array.isArray(
      snapshot?.security?.failed_units
    )
      ? snapshot.security.failed_units
      : [];

  return values
    .map((value) => {
      if (typeof value === "string") {
        return value.trim();
      }

      if (
        value &&
        typeof value === "object"
      ) {
        return String(
          value.name ||
          value.unit ||
          value.id ||
          ""
        ).trim();
      }

      return "";
    })
    .filter(Boolean);
}

function securityFindingCommands(
  insight,
  snapshot
) {
  const fingerprint = String(
    insight?.fingerprint || ""
  ).toLowerCase();

  const title = String(
    insight?.title || ""
  ).toLowerCase();

  const commands = [];

  const add = (
    label,
    command,
    note = ""
  ) => {
    if (!command?.trim()) {
      return;
    }

    commands.push({
      label,
      command: command.trim(),
      note,
    });
  };

  if (
    fingerprint === "pending-updates" ||
    title.includes(
      "updates are pending"
    )
  ) {
    add(
      "Review and apply Ubuntu updates",
      `sudo apt update
apt list --upgradable
sudo apt upgrade

if [ -f /var/run/reboot-required ]; then
  echo "Reboot required by:"
  cat /var/run/reboot-required.pkgs
else
  echo "No reboot is currently required."
fi`,
      (
        "apt upgrade remains interactive so you can " +
        "review the proposed changes before approving them.  " +
        "This does not reboot the VPS automatically."
      )
    );
  }

  if (
    fingerprint ===
      "systemd-failed-units" ||
    title.includes(
      "systemd has failed units"
    )
  ) {
    const units =
      securityFailedUnitNames(snapshot);

    const inspection = [
      "sudo systemctl --failed --no-pager",
    ];

    for (const unit of units) {
      const quoted =
        securityShellQuote(unit);

      inspection.push(
        "",
        `sudo systemctl status ${quoted} --no-pager -l`,
        `sudo journalctl -u ${quoted} --no-pager -n 100`
      );
    }

    add(
      "Inspect failed systemd units",
      inspection.join("\n"),
      (
        "Review the status and journal output before " +
        "restarting or clearing any failed unit."
      )
    );

    const installerUnits =
      units.filter(
        (unit) =>
          unit.startsWith(
            "edgewatch-map-assets-install-"
          )
      );

    if (installerUnits.length) {
      add(
        "Clear obsolete MapLibre installer failures",
        installerUnits
          .map(
            (unit) =>
              `sudo systemctl reset-failed ${
                securityShellQuote(unit)
              }`
          )
          .join("\n"),
        (
          "These are completed transient installer units.  " +
          "The currently installed map remains unaffected."
        )
      );
    }
  }

  if (
    fingerprint.includes(
      "ssh-password"
    ) ||
    title.includes(
      "ssh password authentication"
    )
  ) {
    add(
      "Verify effective SSH authentication settings",
      `sudo sshd -T | grep -E '^(passwordauthentication|pubkeyauthentication|permitrootlogin) '`,
      (
        "This is read-only and confirms the effective " +
        "settings currently enforced by sshd."
      )
    );

    add(
      "Disable password SSH after key access is tested",
      `printf '%s\n' 'PasswordAuthentication no' |
  sudo tee /etc/ssh/sshd_config.d/00-edgewatch-password-auth.conf >/dev/null

sudo sshd -t
sudo systemctl reload ssh

sudo sshd -T |
  grep -E '^(passwordauthentication|pubkeyauthentication|permitrootlogin) '`,
      (
        "Do not run this until a new SSH session as your non-root administrator " +
        "has successfully connected using an SSH key.  " +
        "Keep an existing session open while testing."
      )
    );
  }

  if (
    fingerprint ===
      "service-journal-warnings" ||
    title.includes(
      "service warnings"
    )
  ) {
    add(
      "Review recent monitored-service warnings",
      `sudo journalctl \
  -u caddy \
  -u ssh \
  -u wg-quick@wg0 \
  --since "15 minutes ago" \
  --priority warning \
  --no-pager \
  -o short-iso`,
      "This command only reads the recent service journals."
    );
  }

  if (
    fingerprint === "ufw-inactive" ||
    title.includes("ufw")
  ) {
    add(
      "Inspect the host firewall",
      `sudo ufw status verbose
sudo ss -lntup`,
      (
        "These commands are read-only.  Review listening " +
        "services before changing firewall rules."
      )
    );
  }

  if (
    fingerprint.includes("fail2ban") ||
    title.includes("fail2ban")
  ) {
    add(
      "Inspect Fail2ban",
      `sudo systemctl status fail2ban --no-pager -l
sudo fail2ban-client status`,
      "These commands do not change Fail2ban configuration."
    );
  }

  if (
    fingerprint ===
      "apparmor-inactive" ||
    title.includes("apparmor")
  ) {
    add(
      "Inspect AppArmor",
      `sudo systemctl status apparmor --no-pager -l
sudo aa-status`,
      "Review the service and loaded-profile status first."
    );
  }

  if (
    fingerprint ===
      "time-not-synchronized" ||
    title.includes(
      "time is not synchronized"
    )
  ) {
    add(
      "Inspect and restart time synchronization",
      `timedatectl status
timedatectl timesync-status
sudo systemctl restart systemd-timesyncd
timedatectl timesync-status`,
      (
        "Restarting systemd-timesyncd does not reboot " +
        "the VPS."
      )
    );
  }

  return commands;
}

async function copySecurityFindingCommand(
  command,
  button
) {
  try {
    if (
      navigator.clipboard?.writeText &&
      window.isSecureContext
    ) {
      await navigator.clipboard.writeText(
        command
      );
    } else {
      const textarea =
        document.createElement("textarea");

      textarea.value = command;
      textarea.setAttribute(
        "readonly",
        ""
      );

      textarea.style.position = "fixed";
      textarea.style.opacity = "0";

      document.body.appendChild(
        textarea
      );

      textarea.select();

      const copied =
        document.execCommand("copy");

      textarea.remove();

      if (!copied) {
        throw new Error(
          "Browser copy command failed"
        );
      }
    }

    const previous =
      button.textContent;

    button.textContent = "Copied";
    button.classList.add("copied");

    showToast("Command copied");

    window.setTimeout(() => {
      button.textContent = previous;
      button.classList.remove("copied");
    }, 1400);
  } catch (error) {
    console.error(
      "Could not copy security command",
      error
    );

    showToast(
      "Could not copy the command"
    );
  }
}

function securityFindingCommandCard(
  command
) {
  const card = node(
    "article",
    "security-command-card"
  );

  const header = node(
    "div",
    "security-command-header"
  );

  header.appendChild(
    node(
      "strong",
      "",
      command.label
    )
  );

  const copyButton = node(
    "button",
    "security-command-copy",
    "Copy"
  );

  copyButton.type = "button";

  copyButton.setAttribute(
    "aria-label",
    `Copy command: ${command.label}`
  );

  copyButton.addEventListener(
    "click",
    () =>
      copySecurityFindingCommand(
        command.command,
        copyButton
      )
  );

  header.appendChild(copyButton);
  card.appendChild(header);

  const code = node(
    "pre",
    "security-command-code"
  );

  code.textContent = command.command;

  card.appendChild(code);

  if (command.note) {
    card.appendChild(
      node(
        "p",
        "security-command-note",
        command.note
      )
    );
  }

  return card;
}


function findingAcknowledgementTime(value) {
  if (!value) return "Unknown time";
  const date = new Date(number(value) * 1000);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function activeFindingInsights(snapshot = state.snapshot || {}) {
  const insights = snapshot?.posture?.insights;
  return Array.isArray(insights)
    ? insights.filter((item) => item && typeof item === "object")
    : [];
}

function rebuildAcknowledgedFindings(snapshot) {
  const rows = activeFindingInsights(snapshot)
    .filter((insight) => Boolean(insight.acknowledged))
    .map((insight) => ({
      fingerprint: insight.fingerprint,
      title: insight.title,
      category: insight.category,
      severity: insight.severity,
      score: insight.score,
      detail: insight.detail,
      remediation: insight.remediation,
      acknowledged_at: insight.acknowledgement?.acknowledged_at,
      acknowledged_by: insight.acknowledgement?.acknowledged_by,
      acknowledged_severity: insight.acknowledgement?.acknowledged_severity,
      current_severity: insight.acknowledgement?.current_severity,
    }));

  snapshot.acknowledged_findings = rows;
  if (snapshot.posture) {
    snapshot.posture.acknowledged_findings = rows.length;
  }
}

function applyFindingAcknowledgementLocally(fingerprint, acknowledgement) {
  const snapshot = state.snapshot;
  if (!snapshot) return;

  for (const insight of activeFindingInsights(snapshot)) {
    if (String(insight.fingerprint || "") !== String(fingerprint)) continue;
    insight.acknowledged = Boolean(acknowledgement?.active);
    if (insight.acknowledged) {
      insight.acknowledgement = {
        acknowledged_at: acknowledgement.acknowledged_at,
        acknowledged_by: acknowledgement.acknowledged_by,
        acknowledged_severity: acknowledgement.acknowledged_severity,
        current_severity: acknowledgement.current_severity || insight.severity,
      };
    } else {
      delete insight.acknowledgement;
    }
  }

  rebuildAcknowledgedFindings(snapshot);
  renderPosture(snapshot);
  renderAcknowledgedFindings(snapshot);
}

async function setFindingAcknowledged(insight, acknowledged, button = null) {
  const fingerprint = String(insight?.fingerprint || "").trim();
  if (!fingerprint) {
    showToast("This finding has no stable ID");
    return;
  }

  if (button) {
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
  }

  try {
    const response = await fetch("/api/v1/finding-acknowledgements", {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-EdgeWatch-Action": "finding-acknowledgement",
      },
      body: JSON.stringify({ fingerprint, acknowledged }),
    });

    let payload = {};
    try {
      payload = await response.json();
    } catch (_error) {
      payload = {};
    }

    if (!response.ok) {
      throw new Error(payload.detail || `${response.status} ${response.statusText}`);
    }

    const acknowledgement = payload.acknowledgement || {
      active: acknowledged,
    };
    applyFindingAcknowledgementLocally(fingerprint, acknowledgement);

    const updatedInsight = activeFindingInsights(state.snapshot || {}).find(
      (item) => String(item.fingerprint || "") === fingerprint
    );
    const currentControl = button?.closest(".finding-mute-control");
    if (updatedInsight && currentControl) {
      currentControl.replaceWith(
        findingAcknowledgementControl(updatedInsight, {
          compact: currentControl.classList.contains("compact"),
        })
      );
    }

    showToast(
      acknowledged
        ? "Finding acknowledged and notifications muted"
        : "Alerts resumed for this finding"
    );
  } catch (error) {
    console.error("Finding acknowledgement failed", error);
    showToast(`Update failed: ${error.message}`);
  } finally {
    if (button) {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }
}

function findingAcknowledgementControl(insight, options = {}) {
  const compact = Boolean(options.compact);
  const acknowledged = Boolean(insight?.acknowledged);
  const wrapper = node(
    "div",
    compact ? "finding-mute-control compact" : "finding-mute-control"
  );

  const copy = node("div", "finding-mute-copy");
  copy.appendChild(
    node(
      "strong",
      "",
      acknowledged ? "Notifications muted" : "Acknowledge and mute"
    )
  );
  copy.appendChild(
    node(
      "small",
      "",
      acknowledged
        ? "Finding remains active. Resume alerts when you want repeat events and push notifications again."
        : "Keep the finding visible while stopping repeat events and push notifications."
    )
  );

  if (acknowledged && insight?.acknowledgement) {
    const actor = insight.acknowledgement.acknowledged_by || "Unknown user";
    const when = findingAcknowledgementTime(
      insight.acknowledgement.acknowledged_at
    );
    copy.appendChild(
      node("span", "finding-mute-meta", `Acknowledged by ${actor} · ${when}`)
    );
  }

  const button = node("button", "finding-mute-switch");
  button.type = "button";
  button.setAttribute("role", "switch");
  button.setAttribute("aria-checked", String(acknowledged));
  button.setAttribute(
    "aria-label",
    acknowledged
      ? `Resume alerts for ${insight?.title || "finding"}`
      : `Acknowledge and mute ${insight?.title || "finding"}`
  );
  button.title = acknowledged ? "Resume alerts" : "Acknowledge and mute";
  button.appendChild(node("span", "finding-mute-switch-knob"));
  button.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    setFindingAcknowledged(insight, !acknowledged, button);
  });

  wrapper.appendChild(copy);
  wrapper.appendChild(button);
  return wrapper;
}

function openSecurityFindingDrawer(
  insight,
  snapshot
) {
  const severity =
    String(
      insight?.severity || "info"
    ).toUpperCase();

  const category =
    insight?.category || "General";

  const score =
    number(insight?.score);

  const isFinding = score > 0;

  showInsightDrawer({
    eyebrow: "SECURITY FINDING",

    title:
      insight?.title ||
      "Security finding",

    subtitle:
      `${category} · ${severity} · ` +
      (
        isFinding
          ? "Active now"
          : "Visibility notice"
      ),

    render(body) {
      const stats = node(
        "div",
        "metric-detail-grid security-finding-stats"
      );

      stats.appendChild(
        insightStat(
          "Severity",
          severity
        )
      );

      stats.appendChild(
        insightStat(
          "Category",
          category
        )
      );

      stats.appendChild(
        insightStat(
          "Risk points",
          score
        )
      );

      stats.appendChild(
        insightStat(
          "State",
          isFinding
            ? "Active finding"
            : "Informational"
        )
      );

      body.appendChild(stats);

      body.appendChild(
        insightSection(
          "Why EdgeWatch flagged it"
        )
      );

      const explanation = node(
        "section",
        "security-finding-section"
      );

      explanation.appendChild(
        node(
          "p",
          "",
          insight?.detail ||
            "No explanatory detail was supplied."
        )
      );

      body.appendChild(explanation);

      body.appendChild(
        insightSection(
          "Current technical evidence"
        )
      );

      const evidence = node(
        "div",
        "insight-kv-grid security-finding-evidence"
      );

      for (
        const [label, value]
        of securityFindingEvidence(
          insight,
          snapshot
        )
      ) {
        const row =
          insightRow(label, value);

        if (row) {
          evidence.appendChild(row);
        }
      }

      body.appendChild(evidence);

      body.appendChild(
        insightSection(
          "Recommended action"
        )
      );

      const action = node(
        "section",
        "security-finding-section security-finding-action"
      );

      action.appendChild(
        node(
          "p",
          "",
          insight?.remediation ||
            "Review the evidence and determine whether corrective action is required."
        )
      );

      body.appendChild(action);

      const commands =
        securityFindingCommands(
          insight,
          snapshot
        );

      if (commands.length) {
        body.appendChild(
          insightSection(
            "Commands to run"
          )
        );

        const commandList = node(
          "div",
          "security-command-list"
        );

        for (const command of commands) {
          commandList.appendChild(
            securityFindingCommandCard(
              command
            )
          );
        }

        body.appendChild(commandList);
      }

      if (insight?.fingerprint) {
        body.appendChild(
          insightSection(
            "Alert handling"
          )
        );

        const alertHandling = node(
          "section",
          "security-finding-section security-finding-alert-handling"
        );

        alertHandling.appendChild(
          findingAcknowledgementControl(insight)
        );

        body.appendChild(alertHandling);
      }

      body.appendChild(
        insightSection(
          "Finding identity"
        )
      );

      const identity = node(
        "div",
        "insight-kv-grid"
      );

      for (const [label, value] of [
        [
          "Finding ID",
          insight?.fingerprint ||
            "Not supplied",
        ],
        [
          "Snapshot",
          securityFindingSnapshotTime(
            snapshot
          ),
        ],
      ]) {
        const row =
          insightRow(label, value);

        if (row) {
          identity.appendChild(row);
        }
      }

      body.appendChild(identity);
    },
  });
}

function renderPosture(snapshot) {
  const posture = snapshot.posture || {};
  const insights = Array.isArray(posture.insights) ? posture.insights : [];
  const score = number(posture.risk_score);
  const color = riskColor(score);
  $("riskScore").textContent = String(score);
  $("riskLevel").textContent = posture.risk_level || "unknown";
  $("riskRing").style.setProperty("--risk-angle", `${Math.max(3, score * 3.6)}deg`);
  $("riskRing").style.setProperty("--risk-color", color);
  $("riskLevel").style.color = color;
  $("riskLevel").style.borderColor = `${color}55`;
  $("riskLevel").style.background = `${color}16`;
  $("postureHeadline").textContent = posture.headline || "No active findings";
  $("postureDetail").textContent = posture.detail || "The edge looks normal.";

  const list = $("insightList");
  clear(list);
  if (!insights.length) {
    list.appendChild(node("div", "empty-state", "No findings or visibility notices."));
  }

  for (const insight of insights) {
    const acknowledged = Boolean(insight.acknowledged);
    const item = node(
      "article",
      `insight-item security-finding-link ${insight.severity || "low"}${
        acknowledged ? " acknowledged" : ""
      }`
    );
    item.appendChild(node("div", "insight-bar"));
    const body = node("div", "insight-body");

    const titleRow = node("div", "insight-title-row");
    titleRow.appendChild(node("h3", "", insight.title || "Insight"));
    if (acknowledged) {
      titleRow.appendChild(node("span", "acknowledged-chip", "Muted"));
    }
    body.appendChild(titleRow);
    body.appendChild(node("p", "", insight.detail || ""));
    if (insight.remediation) {
      body.appendChild(
        node("div", "insight-action", `Action: ${insight.remediation}`)
      );
    }
    body.appendChild(
      node(
        "div",
        "insight-meta",
        `${insight.category || "General"} · ${insight.severity || "info"} · ${
          acknowledged ? "Acknowledged" : "Tap for details"
        }`
      )
    );
    if (insight.fingerprint) {
      body.appendChild(findingAcknowledgementControl(insight, { compact: true }));
    }

    item.appendChild(body);

    makeInsightClickable(
      item,
      `Open security finding: ${insight.title || "Security finding"}`,
      () => openSecurityFindingDrawer(insight, snapshot)
    );

    list.appendChild(item);
  }
  $("findingSummary").textContent = `${number(posture.active_findings)} active`;
  $("findingHero").textContent = String(number(posture.active_findings));
}

function renderSystem(snapshot) {
  const system = snapshot.system || {};
  const network = snapshot.network || {};
  const peers = Array.isArray(snapshot.wireguard) ? snapshot.wireguard : [];
  $("cpuMetric").textContent = `${number(system.cpu_percent).toFixed(1)}%`;
  $("memoryMetric").textContent = `${number(system.memory_percent).toFixed(1)}%`;
  $("diskMetric").textContent = `${number(system.disk_percent).toFixed(1)}%`;
  $("inodeMetric").textContent = `${number(system.inode_percent).toFixed(1)}%`;
  $("loadMetric").textContent = number(system.load1).toFixed(2);
  $("connectionMetric").textContent = String(number(network.connections?.established));
  $("wgMetric").textContent = `${peers.filter((peer) => peer.online).length}/${peers.length}`;
  $("uptimeMetric").textContent = formatDuration(system.uptime_seconds);
  $("hostnameMetric").textContent = system.hostname || "VPS";
  setMeter("cpuMeter", system.cpu_percent);
  setMeter("memoryMeter", system.memory_percent);
  setMeter("diskMeter", system.disk_percent);
  setMeter("inodeMeter", system.inode_percent);
}

function formatMegabitsPerSecond(
  bytesPerSecond
) {
  const mbps = Math.max(
    0,
    number(bytesPerSecond)
      * 8
      / 1_000_000
  );

  return `${mbps.toLocaleString(
    undefined,
    {
      minimumFractionDigits:
        mbps < 10 ? 1 : 0,
      maximumFractionDigits: 1,
    }
  )} Mbps`;
}

function formatEstimatedMbps(value) {
  const mbps = Math.max(
    0,
    number(value)
  );

  return `${mbps.toLocaleString(
    undefined,
    {
      minimumFractionDigits:
        mbps < 10 ? 1 : 0,
      maximumFractionDigits: 1,
    }
  )} Mbps`;
}

function isPrivatePlexAddress(value) {
  const address = ewNormalizeAddress(value).toLowerCase();

  if (!address) return false;

  if (address.includes(":")) {
    return (
      address === "::1" ||
      address.startsWith("fe80:") ||
      address.startsWith("fc") ||
      address.startsWith("fd")
    );
  }

  const octets = address.split(".").map((item) => Number(item));

  if (octets.length !== 4 || octets.some((item) => !Number.isInteger(item))) {
    return false;
  }

  return (
    octets[0] === 10 ||
    octets[0] === 127 ||
    (octets[0] === 169 && octets[1] === 254) ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168)
  );
}

function plexSessionScope(snapshot, session) {
  const location = String(session?.location || "").toLowerCase();

  if (["lan", "local"].includes(location)) return "local";
  if (["wan", "remote"].includes(location)) return "remote";

  const address = ewNormalizeAddress(
    session?.address || session?.ip || session?.player_address
  );

  const peers = Array.isArray(snapshot.network?.connections?.public_peers)
    ? snapshot.network.connections.public_peers
    : [];

  if (peers.some((peer) => ewNormalizeAddress(peer.ip) === address)) {
    return "remote";
  }

  if (address && isPrivatePlexAddress(address)) return "local";
  return address ? "remote" : "unknown";
}

function plexTrafficEstimates(snapshot) {
  const sessions = Array.isArray(snapshot.plex?.sessions)
    ? snapshot.plex.sessions
    : [];

  let activeRemoteKbps = 0;
  let pausedRemoteKbps = 0;
  let activeRemoteCount = 0;
  let pausedRemoteCount = 0;
  let localCount = 0;

  for (const session of sessions) {
    const scope = plexSessionScope(snapshot, session);
    const playbackState = String(session.state || "").toLowerCase();
    const bandwidth = Math.max(0, number(session.bandwidth_kbps));

    if (scope === "local") {
      localCount += 1;
      continue;
    }

    if (scope !== "remote") continue;

    if (playbackState === "paused") {
      pausedRemoteKbps += bandwidth;
      pausedRemoteCount += 1;
    } else if (playbackState !== "stopped") {
      activeRemoteKbps += bandwidth;
      activeRemoteCount += 1;
    }
  }

  return {
    activeMbps: activeRemoteKbps / 1000,
    pausedMbps: pausedRemoteKbps / 1000,
    activeRemoteCount,
    pausedRemoteCount,
    localCount,
  };
}

function rollingTrafficAverage(snapshot, seconds = 30) {
  const network = snapshot.network || {};
  const timestamp = Date.parse(snapshot.generated_at || "") || Date.now();
  const sample = {
    timestamp,
    rx: Math.max(0, number(network.rx_rate_bps)),
    tx: Math.max(0, number(network.tx_rate_bps)),
  };

  const samples = state.liveTrafficSamples;
  const last = samples[samples.length - 1];

  if (!last || last.timestamp !== timestamp) {
    samples.push(sample);
  } else {
    samples[samples.length - 1] = sample;
  }

  const cutoff = timestamp - Math.max(5, seconds) * 1000;
  state.liveTrafficSamples = samples.filter((item) => item.timestamp >= cutoff);

  const current = state.liveTrafficSamples;
  const divisor = Math.max(1, current.length);

  return {
    rx: current.reduce((total, item) => total + item.rx, 0) / divisor,
    tx: current.reduce((total, item) => total + item.tx, 0) / divisor,
    samples: current.length,
  };
}

function streamClientDisplayName(session) {
  return session.player || session.device || session.user || "Plex client";
}

function streamClientLocation(snapshot, session) {
  const peer = ewSessionPeer(snapshot, session);

  if (peer) return locationLabel(peer);

  const scope = plexSessionScope(snapshot, session);
  if (scope === "local") return "Local network";
  if (scope === "remote") return "Remote network";
  return session.location || "Location unavailable";
}

function openStreamClientsDrawer(snapshot, options = {}) {
  const sessions = Array.isArray(snapshot.plex?.sessions)
    ? snapshot.plex.sessions
    : [];
  const scopeFilter = options.scope || "all";
  const filtered = sessions.filter((session) => {
    if (scopeFilter === "all") return true;
    return plexSessionScope(snapshot, session) === scopeFilter;
  });
  const remoteCount = sessions.filter(
    (session) => plexSessionScope(snapshot, session) === "remote"
  ).length;
  const localCount = sessions.filter(
    (session) => plexSessionScope(snapshot, session) === "local"
  ).length;

  showInsightDrawer({
    eyebrow: scopeFilter === "remote" ? "REMOTE PLEX CLIENTS" : "PLEX CLIENTS",
    title: scopeFilter === "remote" ? "Remote stream clients" : "Active stream clients",
    subtitle: `${filtered.length} shown · ${remoteCount} remote · ${localCount} local`,
    render(body) {
      if (!filtered.length) {
        body.appendChild(node("div", "metric-detail-note", "No matching Plex stream clients are active."));
        return;
      }

      const list = node("div", "client-list");

      for (const session of filtered) {
        const scope = plexSessionScope(snapshot, session);
        const card = node("article", "client-list-card stream-client-card");
        const heading = node("div", "client-list-heading");
        const copy = node("div", "client-list-copy");

        copy.appendChild(node("strong", "", streamClientDisplayName(session)));
        copy.appendChild(
          node(
            "span",
            "",
            `${session.user || "Unknown viewer"} · ${session.server || "Plex"}`
          )
        );
        copy.appendChild(
          node(
            "small",
            "",
            `${session.title || "Untitled media"}${
              session.subtitle ? ` · ${session.subtitle}` : ""
            }`
          )
        );
        heading.appendChild(copy);
        heading.appendChild(
          node(
            "span",
            `client-scope-chip ${scope}`,
            scope === "local" ? "Local" : scope === "remote" ? "Remote" : "Unknown"
          )
        );
        card.appendChild(heading);

        const details = node("div", "client-list-details");
        for (const [label, value] of [
          ["Playback", session.state || "Unknown"],
          ["Mode", session.mode || "Unknown"],
          ["Bitrate", ewFormatBandwidth(session.bandwidth_kbps)],
          ["Location", streamClientLocation(snapshot, session)],
          ["Address", ewNormalizeAddress(session.address) || "Unavailable"],
        ]) {
          const item = node("div");
          item.appendChild(node("span", "", label));
          item.appendChild(node("strong", "", value));
          details.appendChild(item);
        }
        card.appendChild(details);
        list.appendChild(card);
      }

      body.appendChild(list);
      body.appendChild(
        node(
          "div",
          "metric-detail-note",
          "Local clients do not traverse the EdgeWatch VPS. Remote clients can also temporarily have no sampled TCP socket while a player consumes buffered media."
        )
      );
    },
  });
}

function publicPeersWithRemoteSessions(snapshot, peers) {
  const combined = [...peers];
  const knownAddresses = new Set(
    combined.map((peer) => ewNormalizeAddress(peer.ip)).filter(Boolean)
  );
  const sessions = Array.isArray(snapshot.plex?.sessions)
    ? snapshot.plex.sessions
    : [];

  for (const session of sessions) {
    if (plexSessionScope(snapshot, session) !== "remote") continue;
    if (String(session.state || "").toLowerCase() === "stopped") continue;

    const address = ewNormalizeAddress(
      session.address || session.ip || session.player_address
    );

    if (!address || knownAddresses.has(address)) continue;

    combined.push({
      ip: address,
      display_name: streamClientDisplayName(session),
      connections: 0,
      active: true,
      activity: {
        kind: "plex_stream",
        detail: `Plex · ${session.title || "Active playback"}`,
      },
      synthetic_stream: true,
    });
    knownAddresses.add(address);
  }

  return combined;
}

function openRemoteClientsDrawer(snapshot) {
  const connections = snapshot.network?.connections || {};
  const peers = publicPeersWithRemoteSessions(
    snapshot,
    Array.isArray(connections.public_peers) ? connections.public_peers : []
  );

  showInsightDrawer({
    eyebrow: "VPS REMOTE CLIENTS",
    title: "Remote client list",
    subtitle: `${peers.length} clients represented in the current sample`,
    render(body) {
      if (!peers.length) {
        body.appendChild(node("div", "metric-detail-note", "No remote clients are currently connected."));
        return;
      }

      const list = node("div", "client-list");
      const order = { streaming: 0, admin: 1, service: 2, known: 3, review: 4 };
      const sorted = [...peers].sort((left, right) => {
        const leftCategory = ewConnectionCategory(snapshot, left);
        const rightCategory = ewConnectionCategory(snapshot, right);
        return (
          order[leftCategory.key] - order[rightCategory.key] ||
          ewConnectionDisplayName(left).localeCompare(ewConnectionDisplayName(right))
        );
      });

      for (const peer of sorted) {
        const category = ewConnectionCategory(snapshot, peer);
        const card = node("article", "client-list-card remote-client-card");
        const heading = node("div", "client-list-heading");
        const copy = node("div", "client-list-copy");
        copy.appendChild(node("strong", "", ewConnectionDisplayName(peer)));
        copy.appendChild(
          node(
            "span",
            `connection-kind ${category.key}`,
            `${category.label}${ewConnectionLocation(peer) ? ` · ${ewConnectionLocation(peer)}` : ""}`
          )
        );
        copy.appendChild(node("small", "", ewConnectionActivity(snapshot, peer, category)));
        heading.appendChild(copy);
        heading.appendChild(node("span", `client-scope-chip ${category.key}`, category.label));
        card.appendChild(heading);

        const details = node("div", "client-list-details");
        for (const [label, value] of [
          ["Address", peer.ip],
          ["Sockets", number(peer.connections)],
          ["Direction", peer.direction || (peer.synthetic_stream ? "Buffered stream" : "Unknown")],
          ["Last seen", peer.last_seen_ts ? insightTime(peer.last_seen_ts) : "Current"],
        ]) {
          const item = node("div");
          item.appendChild(node("span", "", label));
          item.appendChild(node("strong", "", value));
          details.appendChild(item);
        }
        card.appendChild(details);
        makeInsightClickable(
          card,
          `Open details for ${ewConnectionDisplayName(peer)}`,
          () => openPeerInsight(peer)
        );
        list.appendChild(card);
      }

      body.appendChild(list);
    },
  });
}

function renderTraffic(snapshot) {
  const network =
    snapshot.network || {};

  const rxBytesPerSecond = number(
    network.rx_rate_bps
  );

  const txBytesPerSecond = number(
    network.tx_rate_bps
  );

  const estimates = plexTrafficEstimates(snapshot);
  const average = rollingTrafficAverage(snapshot, 30);

  $("interfaceName").textContent =
    network.interface || "interface";

  $("rxRate").textContent =
    formatMegabitsPerSecond(
      rxBytesPerSecond
    );

  $("txRate").textContent =
    formatMegabitsPerSecond(
      txBytesPerSecond
    );

  $("measuredOutbound").textContent =
    formatMegabitsPerSecond(average.tx);

  $("activePlexEstimate").textContent =
    formatEstimatedMbps(
      estimates.activeMbps
    );

  $("pausedPlexEstimate").textContent =
    formatEstimatedMbps(estimates.pausedMbps);

  $("trafficComparisonNote").textContent =
    `${estimates.activeRemoteCount} active remote stream${
      estimates.activeRemoteCount === 1 ? "" : "s"
    } · ${estimates.pausedRemoteCount} paused remote · ${
      estimates.localCount
    } local stream${estimates.localCount === 1 ? "" : "s"} excluded · ` +
    `measured over ${Math.max(1, average.samples)} live sample${
      average.samples === 1 ? "" : "s"
    } (up to 30 seconds). Plex bitrate is an estimate and can differ during buffering.`;

  const usingLinode =
    network.monthly_transfer_source
    === "linode_account_api";

  const percent = Math.max(
    0,
    Math.min(
      100,
      number(
        network.monthly_egress_percent
      )
    )
  );

  if (usingLinode) {
    const usedGb = number(
      network.monthly_transfer_used_gb
    );

    const quotaGb = number(
      network.monthly_transfer_quota_gb
    );

    const formatGb = (value) =>
      value.toLocaleString(
        undefined,
        {
          minimumFractionDigits: 0,
          maximumFractionDigits: 2,
        }
      );

    $("monthUsage").textContent =
      `${formatGb(
        usedGb
      )} GB outbound this month · ${percent.toFixed(1)}% used`;

    $("monthlyLimit").textContent =
      `${formatGb(
        quotaGb
      )} GB current Linode quota`;
  } else {
    const monthly = number(
      network.monthly_tx_bytes
    );

    const limit = number(
      network.monthly_transfer_limit_bytes
    );

    $("monthUsage").textContent =
      `${formatBytes(
        monthly
      )} locally observed this month`;

    $("monthlyLimit").textContent =
      `${formatBytes(
        limit,
        0
      )} configured fallback limit`;
  }

  $("transferFill").style.width =
    `${percent}%`;
}

function renderServices(snapshot) {
  const security = snapshot.security || {};
  const services = Array.isArray(security.services) ? security.services : [];
  const grid = $("serviceGrid");
  clear(grid);
  if (!services.length) grid.appendChild(node("div", "empty-state", "No service status data returned."));
  for (const service of services) {
    const card = node("article", "service-card");
    const row = node("div", "row");
    row.appendChild(node("strong", "", service.name));
    row.appendChild(node("span", `health-dot${service.active ? "" : " bad"}`));
    card.appendChild(row);
    card.appendChild(node("small", "", service.active ? "Active" : service.state || "Unavailable"));
    grid.appendChild(card);
  }
  const active = services.filter((item) => item.active).length;
  setStatusBadge($("serviceSummary"), `${active}/${services.length} healthy`, services.length && active === services.length ? "good" : "bad");

  const endpoints = Array.isArray(snapshot.url_checks) ? snapshot.url_checks : [];
  const list = $("endpointList");
  clear(list);
  if (!endpoints.length) list.appendChild(node("div", "empty-state", "No endpoint checks configured."));
  for (const check of endpoints) {
    const item = node("article", "endpoint-item");
    const left = node("div", "endpoint-main");
    left.appendChild(node("strong", "", check.name));
    left.appendChild(node("small", "", check.url));
    item.appendChild(left);
    const side = node("div", "endpoint-side");
    side.appendChild(node("span", `health-dot${check.ok ? "" : " bad"}`));
    const latency = check.latency_ms === null || check.latency_ms === undefined ? String(check.status) : `${check.latency_ms} ms`;
    side.appendChild(node("strong", "", latency));
    const cert = check.certificate || {};
    if (cert.days_remaining !== null && cert.days_remaining !== undefined) side.appendChild(node("small", "", `TLS ${number(cert.days_remaining).toFixed(1)}d`));
    item.appendChild(side);
    list.appendChild(item);
  }
  const ok = endpoints.filter((item) => item.ok).length;
  $("endpointSummary").textContent = `${ok}/${endpoints.length} reachable`;
}

function renderPeers(snapshot) {
  const peers = Array.isArray(snapshot.wireguard) ? snapshot.wireguard : [];
  const list = $("peerList");
  clear(list);
  if (!peers.length) list.appendChild(node("div", "empty-state", "No WireGuard peers returned."));
  for (const peer of peers) {
    const card = node("article", "peer-card");
    const row = node("div", "row");
    const title = node("div");
    title.appendChild(node("strong", "", peer.name || peer.interface));
    title.appendChild(node("small", "", (peer.allowed_ips || []).join(", ") || peer.error || peer.interface));
    row.appendChild(title);
    row.appendChild(node("span", `health-dot${peer.online ? "" : " bad"}`));
    card.appendChild(row);
    const meta = node("div", "peer-meta");
    for (const [label, value] of [
      ["Handshake", ageLabel(peer.handshake_age_seconds)],
      ["Received", peer.rx_human || formatBytes(peer.rx_bytes)],
      ["Sent", peer.tx_human || formatBytes(peer.tx_bytes)],
    ]) {
      const cell = node("div");
      cell.appendChild(node("span", "", label));
      cell.appendChild(node("strong", "", value));
      meta.appendChild(cell);
    }
    card.appendChild(meta);
    list.appendChild(card);
  }
  const online = peers.filter((item) => item.online).length;
  setStatusBadge($("peerSummary"), `${online}/${peers.length} online`, peers.length && online === peers.length ? "good" : "bad");
}

function addRows(container, rows, emptyMessage) {
  clear(container);
  if (!rows.length) {
    container.appendChild(node("div", "empty-state", emptyMessage));
    return;
  }
  for (const [left, right] of rows) {
    const row = node("div", "table-row");
    row.appendChild(node("span", "", left));
    row.appendChild(node("strong", "", right));
    container.appendChild(row);
  }
}

function renderSecurity(snapshot) {
  const security = snapshot.security || {};
  const ssh = security.ssh || {};
  $("sshFailed").textContent = String(number(ssh.failed_total));
  $("sshAccepted").textContent = String(number(ssh.accepted_total));
  addRows($("sshSources"), (ssh.failed_by_ip || []).map(([ip, count]) => [ip, count]), "No failed SSH sources in the current window.");

  const listeners = Array.isArray(security.listeners) ? security.listeners : [];
  const table = $("listenerTable");
  clear(table);
  if (!listeners.length) table.appendChild(node("div", "empty-state", "No listening sockets returned."));
  for (const listener of listeners) {
    const row = node("article", "listener-row");
    row.appendChild(node("span", "protocol", listener.protocol));
    const copy = node("div", "listener-copy");
    copy.appendChild(node("strong", "", `${listener.host}:${listener.port}`));
    copy.appendChild(node("small", "", listener.process || listener.service || "Kernel or unknown process"));
    row.appendChild(copy);
    const expected = !listener.public_bind || listener.allowed;
    row.appendChild(node("span", expected ? "exposure-ok" : "exposure-bad", !listener.public_bind ? "Local" : expected ? "Expected" : "Unexpected"));
    table.appendChild(row);
  }
  const unexpected = security.unexpected_listeners || [];
  setStatusBadge($("listenerSummary"), unexpected.length ? `${unexpected.length} unexpected` : "Expected only", unexpected.length ? "bad" : "good");
}

function locationLabel(peer) {
  const place = [peer.city, peer.region, peer.country_code || peer.country].filter(Boolean).join(", ");
  return place || "Location unavailable";
}

function selectedPublicPeers(connections) {
  if (state.flowScope === "recent") {
    return Array.isArray(connections.recent_public_peers) ? connections.recent_public_peers : [];
  }
  return Array.isArray(connections.public_peers) ? connections.public_peers : [];
}

function renderConnectionMetrics(connections) {
  $("tcpSocketCount").textContent = String(number(connections.established));
  $("publicConnectionCount").textContent = String(number(connections.public_connection_count));
  $("uniquePublicCount").textContent = String(number(connections.unique_public_peer_count, number(connections.public_peer_count)));
  $("internalConnectionCount").textContent = String(number(connections.internal_connection_count));
  $("localConnectionCount").textContent = String(number(connections.loopback_connection_count, number(connections.local_connection_count)));
}


function normalizeInsightAddress(value) {
  const address = String(value || "")
    .replace(/^\[|\]$/g, "")
    .split("%", 1)[0];

  if (address.toLowerCase().startsWith("::ffff:")) {
    return address.slice(7);
  }

  return address;
}

function peerActivity(peer) {
  return peer &&
    peer.activity &&
    typeof peer.activity === "object"
      ? peer.activity
      : {};
}

function peerDisplayName(peer) {
  const activity = peerActivity(peer);

  return (
    activity.device_name ||
    peer.display_name ||
    peer.name ||
    peer.ip ||
    "Unknown peer"
  );
}

function matchingPeerSessions(peer) {
  const peerIp = normalizeInsightAddress(peer.ip);
  const sessions = Array.isArray(
    state.snapshot?.plex?.sessions
  )
    ? state.snapshot.plex.sessions
    : [];

  return sessions.filter(
    (session) =>
      normalizeInsightAddress(session.address) === peerIp
  );
}

function peerActivityLabel(peer) {
  const sessions = matchingPeerSessions(peer);

  if (sessions.length) {
    const session = sessions[0];

    return session.title
      ? `Playing ${session.title}`
      : "Active Plex playback";
  }

  return (
    peerActivity(peer).label ||
    (peer.direction === "inbound"
      ? "Inbound connection"
      : "Network connection")
  );
}

function peerMapDetail(peer) {
  const activity = peerActivity(peer);
  const host = activity.host || "";
  const label = peerActivityLabel(peer);
  const count = number(peer.connections);
  const connectionText =
    `${count} connection${count === 1 ? "" : "s"}`;

  return [
    host,
    label,
    connectionText,
  ].filter(Boolean).join(" · ");
}

function peerListDetail(peer) {
  const activity = peerActivity(peer);
  const services = Array.isArray(peer.services)
    ? peer.services
        .map((item) => item.name)
        .filter(Boolean)
        .slice(0, 2)
        .join(" · ")
    : "";

  const recent = peer.active === false
    ? `last seen ${ageLabel(peer.seconds_since_seen)}`
    : "";

  return [
    peer.ip,
    activity.host,
    peerActivityLabel(peer),
    locationLabel(peer),
    services,
    recent,
  ].filter(Boolean).join(" · ");
}

function peerTooltip(peer) {
  return [
    peerDisplayName(peer),
    peer.ip,
    peerActivity(peer).host,
    peerActivityLabel(peer),
    locationLabel(peer),
  ].filter(Boolean).join(" · ");
}

function insightStat(label, value) {
  const text = String(
    value ?? "Unknown"
  );

  const item = node(
    "div",
    "metric-detail-stat"
  );

  if (text.length > 16) {
    item.classList.add(
      "metric-detail-stat-fit"
    );
  }

  item.title = text;

  item.appendChild(
    node("span", "", label)
  );

  item.appendChild(
    node("strong", "", text)
  );

  return item;
}

function insightSection(title) {
  return node("h3", "insight-section-title", title);
}

function insightRow(label, value) {
  if (
    value === undefined ||
    value === null ||
    value === ""
  ) {
    return null;
  }

  const row = node("div", "insight-kv");
  row.appendChild(node("span", "", label));
  row.appendChild(
    node("strong", "", String(value))
  );
  return row;
}

function insightTime(epoch) {
  const value = number(epoch);

  if (!value) return "";

  return new Date(value * 1000).toLocaleString();
}

function showInsightDrawer({
  eyebrow,
  title,
  subtitle,
  render,
}) {
  const drawer = $("metricDrawer");
  const backdrop = $("metricDrawerBackdrop");
  const body = $("metricDrawerBody");

  if (!drawer || !backdrop || !body) {
    return;
  }

  $("metricDrawerEyebrow").textContent =
    eyebrow || "CONNECTION INSIGHT";
  $("metricDrawerTitle").textContent =
    title || "Details";
  $("metricDrawerSubtitle").textContent =
    subtitle || "";

  clear(body);
  render(body);

  drawer.hidden = false;
  backdrop.hidden = false;
  drawer.setAttribute("aria-hidden", "false");
  document.body.classList.add(
    "metric-drawer-open"
  );

  window.requestAnimationFrame(() => {
    backdrop.classList.add("open");
    drawer.classList.add("open");
  });
}

function closePeerInsightDrawer() {
  const drawer = $("metricDrawer");
  const backdrop = $("metricDrawerBackdrop");

  if (!drawer || !backdrop) return;

  drawer.classList.remove("open");
  backdrop.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
  document.body.classList.remove(
    "metric-drawer-open"
  );

  window.setTimeout(() => {
    drawer.hidden = true;
    backdrop.hidden = true;
  }, 220);
}

function makeInsightClickable(
  element,
  label,
  activate,
) {
  if (!element) return;

  element.classList.add("insight-clickable");
  element.setAttribute("role", "button");
  element.setAttribute("tabindex", "0");
  element.setAttribute("aria-label", label);

  element.addEventListener("click", (event) => {
    event.stopPropagation();
    activate();
  });

  element.addEventListener("keydown", (event) => {
    if (
      event.key === "Enter" ||
      event.key === " "
    ) {
      event.preventDefault();
      event.stopPropagation();
      activate();
    }
  });
}

function openPeerInsight(peer) {
  const activity = peerActivity(peer);
  const sessions = matchingPeerSessions(peer);
  const displayName = peerDisplayName(peer);
  const location = locationLabel(peer);

  showInsightDrawer({
    eyebrow: "PUBLIC CONNECTION",
    title: displayName,
    subtitle: [
      peer.ip,
      location,
      activity.host,
    ].filter(Boolean).join(" · "),

    render(body) {
      const stats = node(
        "div",
        "metric-detail-grid"
      );

      stats.appendChild(
        insightStat(
          "Connections",
          number(peer.connections)
        )
      );
      stats.appendChild(
        insightStat(
          "Direction",
          peer.direction || "Unknown"
        )
      );
      stats.appendChild(
        insightStat(
          "Activity",
          peerActivityLabel(peer)
        )
      );
      stats.appendChild(
        insightStat(
          "Host",
          activity.host || "Not identified"
        )
      );

      body.appendChild(stats);

      if (
        activity.kind === "plex_notification" &&
        !sessions.length
      ) {
        body.appendChild(
          node(
            "div",
            "metric-detail-note insight-good-note",
            "This is a background Plex notification connection. It is not active media playback."
          )
        );
      }

      if (sessions.length) {
        body.appendChild(
          insightSection("Active Plex media")
        );

        for (const session of sessions) {
          const card = node(
            "article",
            "insight-session-card"
          );

          const heading = node(
            "div",
            "insight-session-heading"
          );

          const copy = node("div");
          copy.appendChild(
            node(
              "strong",
              "",
              session.title || "Untitled media"
            )
          );
          copy.appendChild(
            node(
              "small",
              "",
              session.subtitle ||
                session.media_type ||
                "Plex media"
            )
          );

          heading.appendChild(copy);
          heading.appendChild(
            node(
              "span",
              `mode-pill ${modeClass(
                session.mode
              )}`,
              session.mode || "Unknown"
            )
          );

          card.appendChild(heading);

          for (const [label, value] of [
            [
              "Viewer",
              `${session.user || "Unknown"} on ${
                session.player || "Unknown player"
              }`,
            ],
            [
              "Server",
              session.server || "Unknown",
            ],
            [
              "Progress",
              `${number(
                session.progress_percent
              ).toFixed(0)}%`,
            ],
            [
              "Bandwidth",
              `${number(
                session.bandwidth_kbps
              ).toLocaleString()} Kbps`,
            ],
          ]) {
            const row = insightRow(label, value);
            if (row) card.appendChild(row);
          }

          body.appendChild(card);
        }
      }

      body.appendChild(
        insightSection("Client identity")
      );

      const identity = node(
        "div",
        "insight-kv-grid"
      );

      for (const [label, value] of [
        ["Device name", activity.device_name],
        ["Device", activity.device],
        ["Vendor", activity.device_vendor],
        ["Product", activity.product],
        ["Plex version", activity.version],
        ["Platform", activity.platform],
        [
          "Platform version",
          activity.platform_version,
        ],
        ["Model", activity.model],
        [
          "Client identifier",
          activity.client_identifier,
        ],
      ]) {
        const row = insightRow(label, value);
        if (row) identity.appendChild(row);
      }

      if (!identity.children.length) {
        identity.appendChild(
          node(
            "div",
            "metric-detail-note",
            "No application identity headers have been observed for this connection yet."
          )
        );
      }

      body.appendChild(identity);

      body.appendChild(
        insightSection("Network details")
      );

      const network = node(
        "div",
        "insight-kv-grid"
      );

      const services = Array.isArray(
        peer.services
      )
        ? peer.services
            .map(
              (item) =>
                `${item.name} (${item.connections})`
            )
            .join(", ")
        : "";

      for (const [label, value] of [
        ["Public IP", peer.ip],
        ["Location", location],
        ["Organization", peer.organization],
        [
          "ASN",
          peer.asn ? `AS${peer.asn}` : "",
        ],
        ["Requested host", activity.host],
        ["Activity", activity.label],
        [
          "Request",
          activity.method && activity.path
            ? `${activity.method} ${activity.path}`
            : activity.path,
        ],
        ["HTTP status", activity.status],
        ["Services", services],
        [
          "Local ports",
          Array.isArray(peer.local_ports)
            ? peer.local_ports.join(", ")
            : "",
        ],
        [
          "Remote ports",
          Array.isArray(peer.remote_ports)
            ? peer.remote_ports.join(", ")
            : "",
        ],
        [
          "First seen",
          insightTime(peer.first_seen_ts),
        ],
        [
          "Last seen",
          insightTime(peer.last_seen_ts),
        ],
      ]) {
        const row = insightRow(label, value);
        if (row) network.appendChild(row);
      }

      body.appendChild(network);
    },
  });
}

function openWireGuardInsight(snapshot) {
  const peers = Array.isArray(snapshot.wireguard)
    ? snapshot.wireguard
    : [];

  const online = peers.filter(
    (peer) => peer.online
  ).length;

  showInsightDrawer({
    eyebrow: "EDGEWATCH VPS",
    title: "WireGuard peers",
    subtitle:
      `${online}/${peers.length} peers online`,

    render(body) {
      if (!peers.length) {
        body.appendChild(
          node(
            "div",
            "metric-detail-note",
            "No WireGuard peers are configured."
          )
        );
        return;
      }

      for (const peer of peers) {
        const card = node(
          "article",
          `insight-wireguard-card ${
            peer.online ? "good" : "bad"
          }`
        );

        const heading = node(
          "div",
          "insight-session-heading"
        );

        heading.appendChild(
          node(
            "strong",
            "",
            peer.name || "WireGuard peer"
          )
        );

        heading.appendChild(
          node(
            "span",
            peer.online
              ? "status-badge good"
              : "status-badge bad",
            peer.online ? "Online" : "Offline"
          )
        );

        card.appendChild(heading);

        for (const [label, value] of [
          [
            "Allowed IPs",
            Array.isArray(peer.allowed_ips)
              ? peer.allowed_ips.join(", ")
              : "",
          ],
          ["Endpoint", peer.endpoint],
          [
            "Handshake age",
            peer.handshake_age_seconds !== null &&
            peer.handshake_age_seconds !== undefined
              ? formatDuration(
                  peer.handshake_age_seconds
                )
              : "No handshake",
          ],
          ["Received", peer.rx_human],
          ["Sent", peer.tx_human],
          [
            "Public key",
            peer.public_key_short,
          ],
        ]) {
          const row = insightRow(label, value);
          if (row) card.appendChild(row);
        }

        body.appendChild(card);
      }
    },
  });
}

function bindPeerInsightDrawer() {
  const close = $("metricDrawerClose");
  const backdrop = $("metricDrawerBackdrop");

  if (close && !close.dataset.insightBound) {
    close.dataset.insightBound = "true";
    close.addEventListener(
      "click",
      closePeerInsightDrawer
    );
  }

  if (
    backdrop &&
    !backdrop.dataset.insightBound
  ) {
    backdrop.dataset.insightBound = "true";
    backdrop.addEventListener(
      "click",
      closePeerInsightDrawer
    );
  }

  document.addEventListener(
    "keydown",
    (event) => {
      if (
        event.key === "Escape" &&
        !$("metricDrawer")?.hidden
      ) {
        closePeerInsightDrawer();
      }
    }
  );
}

function ewConnectionNormalizeAddress(value) {
  const address = String(value || "")
    .replace(/^\[|\]$/g, "")
    .split("%", 1)[0];

  return address
    .toLowerCase()
    .startsWith("::ffff:")
      ? address.slice(7)
      : address;
}

function ewConnectionDisplayName(peer) {
  return peerDisplayName(peer);
}

function ewConnectionSession(
  snapshot,
  peer
) {
  const address =
    ewConnectionNormalizeAddress(
      peer.ip
    );

  const sessions = Array.isArray(
    snapshot.plex?.sessions
  )
    ? snapshot.plex.sessions
    : [];

  return sessions.find(
    (session) => {
      const sessionAddress =
        ewConnectionNormalizeAddress(
          session.address ||
          session.ip ||
          session.player_address
        );

      const status = String(
        session.state || ""
      ).toLowerCase();

      return (
        sessionAddress === address &&
        status !== "stopped"
      );
    }
  );
}

function ewConnectionLocation(peer) {
  const parts = [
    peer.city,
    peer.region_code || peer.region,
    peer.country_code,
  ].filter(Boolean);

  return parts.join(", ");
}

function ewConnectionCategory(
  snapshot,
  peer
) {
  const address =
    ewConnectionNormalizeAddress(
      peer.ip
    );

  const session =
    ewConnectionSession(
      snapshot,
      peer
    );

  if (session) {
    return {
      key: "streaming",
      label: "Streaming",
      session,
    };
  }

  const activityKind = String(
    peerActivity(peer).kind || ""
  ).toLowerCase();

  if (activityKind === "edgewatch") {
    return {
      key: "admin",
      label: "Admin",
      session: null,
    };
  }

  if (
    activityKind === "plex_notification" ||
    activityKind === "service"
  ) {
    return {
      key: "service",
      label: "Service",
      session: null,
    };
  }

  const displayName = String(
    ewConnectionDisplayName(peer) || ""
  ).trim();

  if (
    displayName &&
    displayName !== peer.ip
  ) {
    return {
      key: "known",
      label: "Known",
      session: null,
    };
  }

  return {
    key: "review",
    label: "Review",
    session: null,
  };
}

function ewConnectionActivity(
  snapshot,
  peer,
  category
) {
  if (category.key === "streaming") {
    const session = category.session || {};

    const title =
      session.title ||
      session.grandparent_title ||
      session.parent_title ||
      "Plex playback";

    return `Plex · Playing ${title}`;
  }

  if (category.key === "admin") {
    return "EdgeWatch dashboard";
  }

  if (category.key === "service") {
    return "Plex notification channel";
  }

  return (
    peerListDetail(peer) ||
    "Remote connection"
  );
}

function ewRenderOperationalCounters(
  snapshot,
  peers
) {
  const categories = peers.map(
    (peer) =>
      ewConnectionCategory(
        snapshot,
        peer
      ).key
  );

  const count = (key) =>
    categories.filter(
      (value) => value === key
    ).length;

  $("remoteClientCount").textContent =
    String(peers.length);

  const streamCounts = plexTrafficEstimates(snapshot);
  $("streamingClientCount").textContent =
    String(streamCounts.activeRemoteCount + streamCounts.pausedRemoteCount);

  $("adminSessionCount").textContent =
    String(count("admin"));

  $("serviceConnectionCount").textContent =
    String(count("service"));

  $("reviewConnectionCount").textContent =
    String(count("review"));
}

function renderFlows(snapshot) {
  const connections =
    snapshot.network?.connections || {};

  const list = $("flowList");

  clear(list);

  renderConnectionMetrics(
    connections
  );

  const selectedPeers = selectedPublicPeers(connections);
  const publicPeers = state.flowScope === "active"
    ? publicPeersWithRemoteSessions(snapshot, selectedPeers)
    : selectedPeers;

  ewRenderOperationalCounters(
    snapshot,
    publicPeers
  );

  if (state.flowKind === "internal") {
    const peers = Array.isArray(
      connections.internal_peers
    )
      ? connections.internal_peers
      : [];

    $("flowTitle").textContent =
      "Internal connections";

    $("flowSummary").textContent =
      `${number(
        connections.internal_connection_count
      )} active sockets`;
    $("flowContext").textContent = "Private LAN and WireGuard connections sampled on the VPS.";

    if (!peers.length) {
      list.appendChild(
        node(
          "div",
          "empty-state",
          "No private or WireGuard TCP " +
          "connections in the current sample."
        )
      );
    }

    for (
      const peer of peers.slice(0, 20)
    ) {
      const card = node(
        "article",
        "flow-card internal"
      );

      const badgeText =
        peer.name &&
        peer.name !== peer.ip
          ? "WG"
          : "LAN";

      card.appendChild(
        node(
          "div",
          "country-badge internal",
          badgeText
        )
      );

      const copy = node(
        "div",
        "flow-copy"
      );

      copy.appendChild(
        node(
          "strong",
          "",
          peer.name || peer.ip
        )
      );

      const service = (
        peer.services || []
      )
        .map((item) => item.name)
        .slice(0, 2)
        .join(" · ");

      const process = (
        peer.processes || []
      )
        .map((item) => item.name)
        .slice(0, 1)
        .join("");

      copy.appendChild(
        node(
          "small",
          "",
          `${peer.ip}` +
          `${service
            ? ` · ${service}`
            : ""}` +
          `${process
            ? ` · ${process}`
            : ""}`
        )
      );

      card.appendChild(copy);

      const count = node(
        "div",
        "flow-count"
      );

      count.appendChild(
        node(
          "strong",
          "",
          "Internal"
        )
      );

      count.appendChild(
        node(
          "span",
          "",
          `${number(
            peer.connections
          )} sockets`
        )
      );

      card.appendChild(count);
      list.appendChild(card);
    }
  } else {
    const peers = publicPeers;

    $("flowTitle").textContent =
      state.flowScope === "recent"
        ? "Recently connected to the VPS"
        : "Who is connected to the VPS now";

    const totalSockets = peers.reduce(
      (total, peer) =>
        total + number(
          peer.connections
        ),
      0
    );

    $("flowSummary").textContent =
      state.flowScope === "recent"
        ? (
            `${peers.length} remote clients · ` +
            `${number(
              connections.flow_recent_seconds,
              60
            )}s window`
          )
        : (
            `${peers.length} remote clients · ` +
            `${totalSockets} sockets`
          );

    const streamCounts = plexTrafficEstimates(snapshot);
    $("flowContext").textContent = state.flowScope === "recent"
      ? "Recently observed VPS connections."
      : `${streamCounts.activeRemoteCount + streamCounts.pausedRemoteCount} remote Plex client${
          streamCounts.activeRemoteCount + streamCounts.pausedRemoteCount === 1 ? "" : "s"
        } use the VPS; ${streamCounts.localCount} local stream${
          streamCounts.localCount === 1 ? "" : "s"
        } stay on the home network and are available from the Streams card.`;

    if (!peers.length) {
      list.appendChild(
        node(
          "div",
          "empty-state",
          state.flowScope === "recent"
            ? (
                "No remote clients were observed " +
                "during the recent window."
              )
            : (
                "No remote clients are connected."
              )
        )
      );
    }

    const order = {
      streaming: 0,
      admin: 1,
      service: 2,
      known: 3,
      review: 4,
    };

    const sortedPeers = [
      ...peers,
    ].sort(
      (left, right) => {
        const leftCategory =
          ewConnectionCategory(
            snapshot,
            left
          );

        const rightCategory =
          ewConnectionCategory(
            snapshot,
            right
          );

        return (
          order[leftCategory.key] -
            order[rightCategory.key] ||
          ewConnectionDisplayName(left)
            .localeCompare(
              ewConnectionDisplayName(right)
            )
        );
      }
    );

    for (
      const peer of sortedPeers.slice(0, 20)
    ) {
      const category =
        ewConnectionCategory(
          snapshot,
          peer
        );

      const card = node(
        "article",
        (
          "flow-card connection-card " +
          `${category.key}` +
          `${peer.active === false
            ? " recent"
            : ""}`
        )
      );

      card.appendChild(
        node(
          "div",
          `country-badge ${category.key}`,
          peer.country_code || "??"
        )
      );

      const copy = node(
        "div",
        "flow-copy"
      );

      copy.appendChild(
        node(
          "strong",
          "",
          ewConnectionDisplayName(peer)
        )
      );

      const location =
        ewConnectionLocation(peer);

      copy.appendChild(
        node(
          "span",
          `connection-kind ${category.key}`,
          (
            category.label +
            `${location
              ? ` · ${location}`
              : ""}`
          )
        )
      );

      copy.appendChild(
        node(
          "small",
          "connection-activity",
          ewConnectionActivity(
            snapshot,
            peer,
            category
          )
        )
      );

      const sockets = number(
        peer.connections
      );

      copy.appendChild(
        node(
          "small",
          "connection-technical",
          (
            `${peer.ip} · ` +
            `${sockets} socket` +
            `${sockets === 1
              ? ""
              : "s"}`
          )
        )
      );

      card.appendChild(copy);

      const side = node(
        "div",
        "flow-count connection-status"
      );

      side.appendChild(
        node(
          "strong",
          "",
          peer.active === false
            ? "Recent"
            : "Now"
        )
      );

      side.appendChild(
        node(
          "span",
          "",
          category.label
        )
      );

      card.appendChild(side);

      makeInsightClickable(
        card,
        (
          "Open details for " +
          ewConnectionDisplayName(peer)
        ),
        () => openPeerInsight(peer)
      );

      list.appendChild(card);
    }
  }

  $("peerHero").textContent = String(
    number(
      connections.unique_public_peer_count,
      number(
        connections.public_peer_count
      )
    )
  );
}

function project(longitude, latitude) {
  return {
    x: ((number(longitude) + 180) / 360) * 1000,
    y: ((90 - number(latitude)) / 180) * 500,
  };
}

function addMapLabel(
  parent,
  x,
  y,
  titleText,
  detailText,
  align = "right",
  className = "",
  offsetY = 0
) {
  const title = String(
    titleText || "Connection"
  );

  const display =
    title.length > 26
      ? `${title.slice(0, 25)}…`
      : title;

  const width = Math.max(
    88,
    Math.min(
      180,
      22 + display.length * 6.2
    )
  );

  const height = 28;
  const gap = 18;

  let left =
    align === "left"
      ? x - width - gap
      : x + gap;

  left = Math.max(
    8,
    Math.min(
      1000 - width - 8,
      left
    )
  );

  let top =
    y - height / 2 + number(offsetY);

  top = Math.max(
    8,
    Math.min(
      500 - height - 8,
      top
    )
  );

  const anchorX =
    align === "left"
      ? left + width
      : left;

  const anchorY =
    top + height / 2;

  parent.appendChild(
    svgNode(
      "line",
      {
        x1: x,
        y1: y,
        x2: anchorX,
        y2: anchorY,
        class:
          `map-label-link compact ${className}`.trim(),
      }
    )
  );

  const group = svgNode(
    "g",
    {
      class:
        `map-callout compact ${className}`.trim(),
    }
  );

  group.appendChild(
    svgNode(
      "rect",
      {
        x: left,
        y: top,
        width,
        height,
        rx: 8,
      }
    )
  );

  const label = svgNode(
    "text",
    {
      x: left + 10,
      y: top + 18,
      class:
        "map-callout-title compact",
    }
  );

  label.textContent = display;

  group.appendChild(label);
  parent.appendChild(group);

  return group;
}

function ewReadConnectionMapView() {
  const svg = $("connectionMap");

  const values = String(
    svg?.getAttribute("viewBox") ||
    "0 0 1000 500"
  )
    .trim()
    .split(/\s+/)
    .map(Number);

  if (
    values.length !== 4 ||
    values.some(
      (value) => !Number.isFinite(value)
    )
  ) {
    return {
      x: 0,
      y: 0,
      width: 1000,
      height: 500,
    };
  }

  return {
    x: values[0],
    y: values[1],
    width: values[2],
    height: values[3],
  };
}

function ewConnectionMapRect() {
  const svg = $("connectionMap");
  const rect =
    svg?.getBoundingClientRect();

  return {
    width: Math.max(
      1,
      rect?.width ||
      svg?.clientWidth ||
      1000
    ),

    height: Math.max(
      1,
      rect?.height ||
      svg?.clientHeight ||
      500
    ),
  };
}

function ewClampConnectionMapView(view) {
  let width = Math.max(
    150,
    number(view.width, 1000)
  );

  let height = Math.max(
    75,
    number(view.height, 500)
  );

  const scale = Math.min(
    1,
    1000 / width,
    500 / height
  );

  width *= scale;
  height *= scale;

  const maxX = Math.max(
    0,
    1000 - width
  );

  const maxY = Math.max(
    0,
    500 - height
  );

  return {
    x: Math.max(
      0,
      Math.min(
        maxX,
        number(view.x)
      )
    ),

    y: Math.max(
      0,
      Math.min(
        maxY,
        number(view.y)
      )
    ),

    width,
    height,
  };
}

function ewApplyConnectionMapView(
  view,
  manual = false
) {
  const svg = $("connectionMap");

  if (!svg) return;

  const clamped =
    ewClampConnectionMapView(view);

  state.connectionMapView =
    clamped;

  state.connectionMapManual =
    Boolean(manual);

  svg.setAttribute(
    "viewBox",
    [
      clamped.x.toFixed(2),
      clamped.y.toFixed(2),
      clamped.width.toFixed(2),
      clamped.height.toFixed(2),
    ].join(" ")
  );

  svg.setAttribute(
    "preserveAspectRatio",
    "xMidYMid meet"
  );
}

function ewConnectionMapClientToWorld(
  clientX,
  clientY,
  view = null
) {
  const svg = $("connectionMap");
  const rect =
    svg?.getBoundingClientRect();

  const current =
    view ||
    state.connectionMapView ||
    ewReadConnectionMapView();

  if (!rect) {
    return {
      x:
        current.x +
        current.width / 2,

      y:
        current.y +
        current.height / 2,
    };
  }

  const relativeX = Math.max(
    0,
    Math.min(
      1,
      (clientX - rect.left) /
      Math.max(1, rect.width)
    )
  );

  const relativeY = Math.max(
    0,
    Math.min(
      1,
      (clientY - rect.top) /
      Math.max(1, rect.height)
    )
  );

  return {
    x:
      current.x +
      current.width * relativeX,

    y:
      current.y +
      current.height * relativeY,
  };
}

function ewZoomConnectionMap(
  factor,
  clientX = null,
  clientY = null
) {
  const svg = $("connectionMap");

  if (!svg) return;

  const current =
    state.connectionMapView ||
    ewReadConnectionMapView();

  const rect =
    svg.getBoundingClientRect();

  const anchorClientX =
    Number.isFinite(clientX)
      ? clientX
      : rect.left + rect.width / 2;

  const anchorClientY =
    Number.isFinite(clientY)
      ? clientY
      : rect.top + rect.height / 2;

  const anchor =
    ewConnectionMapClientToWorld(
      anchorClientX,
      anchorClientY,
      current
    );

  const relativeX = Math.max(
    0,
    Math.min(
      1,
      (
        anchorClientX -
        rect.left
      ) / Math.max(1, rect.width)
    )
  );

  const relativeY = Math.max(
    0,
    Math.min(
      1,
      (
        anchorClientY -
        rect.top
      ) / Math.max(1, rect.height)
    )
  );

  const width =
    current.width * factor;

  const height =
    current.height * factor;

  ewApplyConnectionMapView(
    {
      x:
        anchor.x -
        width * relativeX,

      y:
        anchor.y -
        height * relativeY,

      width,
      height,
    },
    true
  );
}

function ensureConnectionMapInteraction() {
  const svg = $("connectionMap");

  const stage =
    svg?.closest(".map-stage");

  if (!svg || !stage) return;

  let controls =
    $("mapZoomControls");

  if (!controls) {
    controls = node(
      "div",
      "map-zoom-controls"
    );

    controls.id =
      "mapZoomControls";

    controls.setAttribute(
      "aria-label",
      "Map zoom controls"
    );
  }

  if (!controls.childElementCount) {
    const actions = [
      {
        action: "fit",
        text: "Fit",
        label: "Fit active connections",
      },
      {
        action: "world",
        text: "World",
        label: "Show full world map",
      },
      {
        action: "in",
        text: "+",
        label: "Zoom in",
      },
      {
        action: "out",
        text: "−",
        label: "Zoom out",
      },
    ];

    for (const item of actions) {
      const button = node(
        "button",
        "",
        item.text
      );

      button.type = "button";

      button.dataset.mapAction =
        item.action;

      button.setAttribute(
        "aria-label",
        item.label
      );

      button.title =
        item.label;

      controls.appendChild(button);
    }

    controls.addEventListener(
      "click",
      (event) => {
        const button =
          event.target.closest(
            "button[data-map-action]"
          );

        if (!button) return;

        event.preventDefault();
        event.stopPropagation();

        const action =
          button.dataset.mapAction;

        if (action === "fit") {
          state.connectionMapManual =
            false;

          fitConnectionMap(
            state.connectionMapFocusPoints ||
            [],
            true
          );
        } else if (
          action === "world"
        ) {
          ewApplyConnectionMapView(
            {
              x: 0,
              y: 0,
              width: 1000,
              height: 500,
            },
            true
          );
        } else if (
          action === "in"
        ) {
          ewZoomConnectionMap(0.75);
        } else if (
          action === "out"
        ) {
          ewZoomConnectionMap(1.333);
        }
      }
    );

    stage.appendChild(controls);
  }

  controls.classList.remove(
    "hidden"
  );

  if (
    svg.dataset.dynamicZoomBound ===
    "true"
  ) {
    return;
  }

  svg.dataset.dynamicZoomBound =
    "true";

  const pointers = new Map();

  let gesture = null;
  let suppressClick = false;

  const currentView = () => ({
    ...(
      state.connectionMapView ||
      ewReadConnectionMapView()
    ),
  });

  const beginSinglePointer = () => {
    if (pointers.size !== 1) return;

    const pointer = [
      ...pointers.values(),
    ][0];

    gesture = {
      type: "drag",
      startX: pointer.x,
      startY: pointer.y,
      startView: currentView(),
    };
  };

  const beginPinch = () => {
    if (pointers.size < 2) return;

    const [first, second] = [
      ...pointers.values(),
    ].slice(0, 2);

    const midpoint = {
      x:
        (first.x + second.x) / 2,

      y:
        (first.y + second.y) / 2,
    };

    const distance = Math.max(
      1,
      Math.hypot(
        second.x - first.x,
        second.y - first.y
      )
    );

    const startView =
      currentView();

    gesture = {
      type: "pinch",
      startDistance: distance,
      startView,
      anchor:
        ewConnectionMapClientToWorld(
          midpoint.x,
          midpoint.y,
          startView
        ),
    };
  };

  svg.addEventListener(
    "pointerdown",
    (event) => {
      if (state.mapMode !== "world") {
        return;
      }

      event.preventDefault();

      pointers.set(
        event.pointerId,
        {
          x: event.clientX,
          y: event.clientY,
        }
      );

      try {
        svg.setPointerCapture(
          event.pointerId
        );
      } catch (_error) {
        // Pointer capture may be unavailable.
      }

      svg.classList.add(
        "map-dragging"
      );

      if (pointers.size === 1) {
        beginSinglePointer();
      } else {
        beginPinch();
      }
    }
  );

  svg.addEventListener(
    "pointermove",
    (event) => {
      if (
        !pointers.has(event.pointerId)
      ) {
        return;
      }

      event.preventDefault();

      pointers.set(
        event.pointerId,
        {
          x: event.clientX,
          y: event.clientY,
        }
      );

      const rect =
        svg.getBoundingClientRect();

      if (pointers.size === 1) {
        if (
          !gesture ||
          gesture.type !== "drag"
        ) {
          beginSinglePointer();
        }

        const pointer = [
          ...pointers.values(),
        ][0];

        const pixelX =
          pointer.x - gesture.startX;

        const pixelY =
          pointer.y - gesture.startY;

        if (
          Math.hypot(
            pixelX,
            pixelY
          ) > 5
        ) {
          suppressClick = true;
        }

        ewApplyConnectionMapView(
          {
            x:
              gesture.startView.x -
              (
                pixelX /
                Math.max(1, rect.width)
              ) *
              gesture.startView.width,

            y:
              gesture.startView.y -
              (
                pixelY /
                Math.max(1, rect.height)
              ) *
              gesture.startView.height,

            width:
              gesture.startView.width,

            height:
              gesture.startView.height,
          },
          true
        );
      } else {
        if (
          !gesture ||
          gesture.type !== "pinch"
        ) {
          beginPinch();
        }

        const [first, second] = [
          ...pointers.values(),
        ].slice(0, 2);

        const distance = Math.max(
          1,
          Math.hypot(
            second.x - first.x,
            second.y - first.y
          )
        );

        const midpoint = {
          x:
            (first.x + second.x) / 2,

          y:
            (first.y + second.y) / 2,
        };

        const factor =
          gesture.startDistance /
          distance;

        const width =
          gesture.startView.width *
          factor;

        const height =
          gesture.startView.height *
          factor;

        const relativeX = Math.max(
          0,
          Math.min(
            1,
            (
              midpoint.x -
              rect.left
            ) /
            Math.max(1, rect.width)
          )
        );

        const relativeY = Math.max(
          0,
          Math.min(
            1,
            (
              midpoint.y -
              rect.top
            ) /
            Math.max(1, rect.height)
          )
        );

        suppressClick = true;

        ewApplyConnectionMapView(
          {
            x:
              gesture.anchor.x -
              width * relativeX,

            y:
              gesture.anchor.y -
              height * relativeY,

            width,
            height,
          },
          true
        );
      }
    }
  );

  const endPointer = (event) => {
    pointers.delete(
      event.pointerId
    );

    try {
      svg.releasePointerCapture(
        event.pointerId
      );
    } catch (_error) {
      // Pointer capture may already be released.
    }

    gesture = null;

    if (!pointers.size) {
      svg.classList.remove(
        "map-dragging"
      );
    } else if (
      pointers.size === 1
    ) {
      beginSinglePointer();
    } else {
      beginPinch();
    }
  };

  svg.addEventListener(
    "pointerup",
    endPointer
  );

  svg.addEventListener(
    "pointercancel",
    endPointer
  );

  svg.addEventListener(
    "wheel",
    (event) => {
      if (state.mapMode !== "world") {
        return;
      }

      event.preventDefault();

      ewZoomConnectionMap(
        event.deltaY < 0
          ? 0.82
          : 1.22,
        event.clientX,
        event.clientY
      );
    },
    {
      passive: false,
    }
  );

  svg.addEventListener(
    "dblclick",
    (event) => {
      event.preventDefault();

      ewZoomConnectionMap(
        0.72,
        event.clientX,
        event.clientY
      );
    }
  );

  svg.addEventListener(
    "click",
    (event) => {
      if (!suppressClick) return;

      suppressClick = false;

      event.preventDefault();
      event.stopImmediatePropagation();
    },
    true
  );
}

function fitConnectionMap(
  points,
  force = false
) {
  const svg = $("connectionMap");

  if (!svg) return;

  const normalized = (
    Array.isArray(points)
      ? points
      : []
  )
    .map(
      (point) => ({
        x: number(point.x),
        y: number(point.y),
      })
    )
    .filter(
      (point) =>
        Number.isFinite(point.x) &&
        Number.isFinite(point.y)
    );

  state.connectionMapFocusPoints =
    normalized;

  if (
    state.connectionMapManual &&
    !force &&
    state.connectionMapView
  ) {
    ewApplyConnectionMapView(
      state.connectionMapView,
      true
    );

    return;
  }

  if (!normalized.length) {
    ewApplyConnectionMapView(
      {
        x: 0,
        y: 0,
        width: 1000,
        height: 500,
      },
      false
    );

    return;
  }

  const xs = normalized.map(
    (point) => point.x
  );

  const ys = normalized.map(
    (point) => point.y
  );

  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);

  const contentWidth = Math.max(
    1,
    maxX - minX
  );

  const contentHeight = Math.max(
    1,
    maxY - minY
  );

  const rect =
    ewConnectionMapRect();

  const aspect = Math.max(
    1.25,
    rect.width / rect.height
  );

  /*
   * Fit to the actual VPS and endpoint dots.
   * Labels are deliberately excluded so they
   * cannot force the view back to the world.
   */
  let viewWidth = Math.max(
    300,
    contentWidth + 150
  );

  let viewHeight = Math.max(
    150,
    contentHeight + 105
  );

  if (
    viewWidth / viewHeight < aspect
  ) {
    viewWidth =
      viewHeight * aspect;
  } else {
    viewHeight =
      viewWidth / aspect;
  }

  const centerX =
    (minX + maxX) / 2;

  const centerY =
    (minY + maxY) / 2;

  state.connectionMapManual =
    false;

  ewApplyConnectionMapView(
    {
      x:
        centerX -
        viewWidth / 2,

      y:
        centerY -
        viewHeight / 2,

      width: viewWidth,
      height: viewHeight,
    },
    false
  );
}

function spreadConnectionEndpoints(items) {
  // EdgeWatch true GeoIP anchors
  const groups = [];
  const overlapDistance = 14;

  for (const item of items) {
    const point =
      item.geoEnd || item.end;

    let group = groups.find(
      (candidate) =>
        Math.hypot(
          candidate.x - point.x,
          candidate.y - point.y
        ) < overlapDistance
    );

    if (!group) {
      group = {
        x: point.x,
        y: point.y,
        sumX: 0,
        sumY: 0,
        items: [],
      };

      groups.push(group);
    }

    group.items.push(item);
    group.sumX += point.x;
    group.sumY += point.y;

    group.x =
      group.sumX /
      group.items.length;

    group.y =
      group.sumY /
      group.items.length;
  }

  for (const group of groups) {
    const count = group.items.length;

    if (count === 1) {
      const item = group.items[0];

      item.end = {
        x: item.geoEnd.x,
        y: item.geoEnd.y,
      };

      continue;
    }

    /*
     * Keep the true GeoIP point unchanged.
     * Only the large interactive marker is
     * fanned out for readability.
     */
    const radius = Math.min(
      20,
      10 + count * 2
    );

    group.items.forEach(
      (item, index) => {
        const angle =
          -Math.PI / 2 +
          (
            Math.PI * 2 * index
          ) / count;

        item.end = {
          x: Math.max(
            12,
            Math.min(
              988,
              group.x +
                Math.cos(angle) *
                radius
            )
          ),

          y: Math.max(
            12,
            Math.min(
              488,
              group.y +
                Math.sin(angle) *
                radius
            )
          ),
        };
      }
    );
  }

  return items;
}

function edgeWatchMapLibrePayload(snapshot) {
  const connections =
    snapshot.network?.connections || {};

  const allPeers =
    selectedPublicPeers(connections);

  const peers = allPeers
    .filter(
      (peer) =>
        peer.located &&
        Number.isFinite(
          Number(peer.longitude)
        ) &&
        Number.isFinite(
          Number(peer.latitude)
        )
    )
    .slice(0, 75)
    .map((peer) => {
      const category =
        ewConnectionCategory(
          snapshot,
          peer
        );

      return {
        ...peer,
        displayName:
          ewConnectionDisplayName(peer),
        detail: peerMapDetail(peer),
        category: category.key,
        accuracyRadiusKm: number(
          peer.accuracy_radius_km
        ),
      };
    });

  const sourceOrigin =
    connections.origin?.located
      ? connections.origin
      : null;

  const origin = sourceOrigin
    ? {
        ...sourceOrigin,
        displayName: "EdgeWatch VPS",
      }
    : null;

  return {
    connections,
    allPeers,
    peers,
    origin,
  };
}

function applyMapLibreWorldState(
  snapshot,
  payload
) {
  const connections = payload.connections;

  $("connectionMap").classList.add(
    "hidden"
  );

  $("topologyMap").classList.add(
    "hidden"
  );

  $("connectionMapLibre")
    ?.classList.remove("hidden");

  $("mapZoomControls")
    ?.classList.add("hidden");

  $("mapLegend")
    .classList.remove("hidden");

  $("mapEmpty").style.display =
    payload.origin || payload.peers.length
      ? "none"
      : "grid";

  if (
    !payload.origin &&
    !payload.peers.length
  ) {
    $("mapEmpty").textContent =
      "Install the local GeoLite2 databases to place public IPs on the map.";
  }

  if (state.flowScope === "recent") {
    $("mapSummary").textContent =
      `${payload.allPeers.length} IPs seen in ` +
      `${number(
        connections.flow_recent_seconds,
        60
      )}s · ${payload.peers.length} mapped`;
  } else {
    $("mapSummary").textContent =
      `${number(
        connections.public_connection_count
      )} public connections · ` +
      `${number(
        connections.unique_public_peer_count,
        number(connections.public_peer_count)
      )} IPs`;
  }

  $("mapNote").textContent =
    "MapLibre uses the locally hosted PMTiles basemap. " +
    "Markers stay at the unmodified GeoIP coordinates, " +
    "shaded areas show the MaxMind accuracy radius, and " +
    "overlapping clients form a tappable cluster.";
}

function openMapClusterDrawer(peers) {
  const drawer = $("metricDrawer");
  const backdrop = $("metricDrawerBackdrop");
  const title = $("metricDrawerTitle");
  const subtitle = $("metricDrawerSubtitle");
  const body = $("metricDrawerBody");

  if (
    !drawer ||
    !backdrop ||
    !title ||
    !subtitle ||
    !body
  ) {
    return;
  }

  const uniquePeers = [...new Map(
    (Array.isArray(peers) ? peers : [])
      .filter((peer) => peer?.ip)
      .map((peer) => [String(peer.ip), peer])
  ).values()];

  title.textContent = "Connections in this area";
  subtitle.textContent =
    `${uniquePeers.length} clients share this approximate GeoIP area`;

  clear(body);

  if (!uniquePeers.length) {
    body.appendChild(
      node(
        "div",
        "metric-detail-note",
        "No client details are available for this map cluster."
      )
    );
  }

  for (const peer of uniquePeers) {
    const row = connectionDetailRow(peer);
    const rowTitle = row.querySelector(
      ".metric-detail-main strong"
    );

    if (rowTitle) {
      rowTitle.textContent =
        peerDisplayName(peer);
    }

    row.classList.add("map-cluster-detail-row");
    makeInsightClickable(
      row,
      `Open details for ${peerDisplayName(peer)}`,
      () => openPeerInsight(peer)
    );
    body.appendChild(row);
  }

  body.appendChild(
    node(
      "div",
      "metric-detail-note",
      "Clustering keeps clients at their true GeoIP coordinates.  Select a client above for its full connection details."
    )
  );

  drawer.hidden = false;
  backdrop.hidden = false;
  drawer.setAttribute("aria-hidden", "false");
  document.body.classList.add("metric-drawer-open");

  window.requestAnimationFrame(() => {
    backdrop.classList.add("open");
    drawer.classList.add("open");
  });
}

// EdgeWatch MapLibre browser diagnostics

function showMapLibreFallbackDiagnostics(
  engine,
  caughtError = null
) {
  const note = $("mapNote");

  if (!note) {
    return;
  }

  let diagnostics = {};

  try {
    diagnostics =
      typeof engine?.diagnostics === "function"
        ? engine.diagnostics()
        : {};
  } catch (error) {
    diagnostics = {
      diagnosticError: String(
        error?.message || error
      ),
    };
  }

  let webgl = false;
  let webgl2 = false;
  let webglError = "";

  try {
    const canvas =
      document.createElement("canvas");

    webgl2 = Boolean(
      canvas.getContext("webgl2")
    );

    webgl =
      webgl2 ||
      Boolean(
        canvas.getContext("webgl") ||
        canvas.getContext(
          "experimental-webgl"
        )
      );
  } catch (error) {
    webglError = String(
      error?.message || error
    );
  }

  const container =
    $("connectionMapLibre");

  const rectangle =
    container?.getBoundingClientRect();

  const computed =
    container
      ? window.getComputedStyle(container)
      : null;

  const libraries =
    diagnostics.libraries || {};

  const caughtMessage = String(
    caughtError?.message ||
    caughtError ||
    ""
  );

  const lastError =
    caughtMessage ||
    diagnostics.lastError ||
    diagnostics.diagnosticError ||
    "No browser error was recorded";

  const values = [
    "MapLibre fallback diagnostics",
    `error=${lastError}`,
    (
      "libraries:" +
      ` maplibre=${
        libraries.maplibre ??
        Boolean(window.maplibregl)
      }` +
      ` pmtiles=${
        libraries.pmtiles ??
        Boolean(window.pmtiles)
      }` +
      ` basemaps=${
        libraries.basemaps ??
        Boolean(window.basemaps)
      }`
    ),
    (
      `workerSetter=${
        libraries.setWorkerUrl ??
        Boolean(
          window.maplibregl &&
          typeof window.maplibregl
            .setWorkerUrl === "function"
        )
      }`
    ),
    (
      `version=${
        window.maplibregl?.version ||
        "unknown"
      }`
    ),
    `webgl=${webgl}`,
    `webgl2=${webgl2}`,
    (
      `secureContext=${
        window.isSecureContext
      }`
    ),
    (
      `container=${
        Math.round(
          rectangle?.width || 0
        )
      }x${
        Math.round(
          rectangle?.height || 0
        )
      }`
    ),
    (
      `display=${
        computed?.display || "missing"
      }`
    ),
    (
      `visibility=${
        computed?.visibility || "missing"
      }`
    ),
  ];

  if (webglError) {
    values.push(
      `webglError=${webglError}`
    );
  }

  note.textContent = values.join(" · ");

  note.classList.add(
    "maplibre-fallback-diagnostic"
  );

  console.error(
    "EdgeWatch MapLibre fallback diagnostics",
    {
      lastError,
      diagnostics,
      webgl,
      webgl2,
      webglError,
      container: {
        width: rectangle?.width || 0,
        height: rectangle?.height || 0,
        display: computed?.display || "",
        visibility:
          computed?.visibility || "",
      },
    }
  );
}

function renderWorldMapPreferred(snapshot) {
  const engine =
    window.EdgeWatchMapLibre;

  if (
    !engine ||
    !engine.canAttempt()
  ) {
    engine?.hide();

    $("connectionMapLibre")
      ?.classList.add("hidden");

    renderWorldMap(snapshot);

    showMapLibreFallbackDiagnostics(
      engine
    );

    return;
  }

  const payload =
    edgeWatchMapLibrePayload(snapshot);

  const token =
    ++state.mapRenderToken;

  if (!engine.isActive()) {
    renderWorldMap(snapshot);
  }

  void engine
    .render(
      {
        origin: payload.origin,
        peers: payload.peers,
      },
      {
        onPeer: (peer) =>
          openPeerInsight(peer),

        onOrigin: () =>
          openWireGuardInsight(snapshot),

        onCluster: (clusterPeers) =>
          openMapClusterDrawer(clusterPeers),
      }
    )
    .then((used) => {
      if (
        token !== state.mapRenderToken ||
        state.mapMode !== "world"
      ) {
        return;
      }

      if (used) {
        applyMapLibreWorldState(
          snapshot,
          payload
        );
      } else {
        engine.hide();
        renderWorldMap(snapshot);

        showMapLibreFallbackDiagnostics(
          engine
        );
      }
    })
    .catch((error) => {
      console.error(
        "MapLibre render failed",
        error
      );

      if (
        token === state.mapRenderToken &&
        state.mapMode === "world"
      ) {
        engine.hide();
        renderWorldMap(snapshot);

        showMapLibreFallbackDiagnostics(
          engine,
          error
        );
      }
    });
}

function renderWorldMap(snapshot) {
  window.EdgeWatchMapLibre?.hide();
  $("connectionMapLibre")?.classList.add("hidden");

  const connections = snapshot.network?.connections || {};
  const allPeers = selectedPublicPeers(connections);
  const peers = allPeers.filter((peer) => peer.located);
  const origin = connections.origin?.located ? connections.origin : null;

  const mapClientSignature = [
    origin?.ip || "",
    ...peers
      .map(
        (peer) =>
          `${peer.ip}:` +
          `${peer.longitude}:` +
          `${peer.latitude}`
      )
      .sort(),
  ].join("|");

  if (
    state.connectionMapClientSignature !==
    mapClientSignature
  ) {
    state.connectionMapClientSignature =
      mapClientSignature;

    state.connectionMapManual =
      false;
  }

  const links = $("mapLinks");
  const markers = $("mapMarkers");
  const labels = $("mapLabels");
  const focusBounds = [];

  ensureConnectionMapInteraction();

  $("mapZoomControls")
    ?.classList.remove("hidden");

  clear(links);
  clear(markers);
  clear(labels);

  $("connectionMap").classList.remove("hidden");
  $("topologyMap").classList.add("hidden");
  $("mapLegend").classList.remove("hidden");
  $("mapNote").textContent = "Small solid dots show the approximate GeoIP location. Nearby interactive markers and labels may be offset and connected back to that location for readability.";

  if (!origin && !peers.length) {
    $("mapEmpty").style.display = "grid";
    $("mapSummary").textContent = `${allPeers.length} public peers · no mapped locations`;
    fitConnectionMap([]);
    return;
  }
  $("mapEmpty").style.display = "none";
  if (state.flowScope === "recent") {
    $("mapSummary").textContent = `${allPeers.length} IPs seen in ${number(connections.flow_recent_seconds, 60)}s · ${peers.length} mapped`;
  } else {
    $("mapSummary").textContent = `${number(connections.public_connection_count)} public connections · ${number(connections.unique_public_peer_count, number(connections.public_peer_count))} IPs`;
  }

  let start = { x: 500, y: 250 };
  if (origin) {
    start = project(origin.longitude, origin.latitude);
    const originGroup = svgNode("g", { class: "map-origin" });
    originGroup.appendChild(svgNode("circle", { cx: start.x, cy: start.y, r: 7 }));
    originGroup.appendChild(svgNode("circle", { cx: start.x, cy: start.y, r: 15, class: "map-origin-ring" }));
    const title = svgNode("title");
    title.textContent = `EdgeWatch VPS · ${origin.ip} · ${locationLabel(origin)}`;
    originGroup.appendChild(title);
    makeInsightClickable(
      originGroup,
      "Open WireGuard peer details",
      () => openWireGuardInsight(snapshot)
    );

    markers.appendChild(originGroup);
    focusBounds.push({
      x: start.x,
      y: start.y,
    });

    const originLabel = addMapLabel(
      labels,
      start.x,
      start.y,
      "EdgeWatch VPS",
      `${origin.ip} · ${locationLabel(origin)}`,
      "right",
      "origin",
      -115,
    );

    // Clickable map label: EdgeWatch VPS
    originLabel.style.pointerEvents = "all";
    originLabel.style.cursor = "pointer";

    makeInsightClickable(
      originLabel,
      "Open WireGuard peer details",
      () => openWireGuardInsight(snapshot)
    );

    // Label dimensions are excluded from automatic map framing.
  }

  const plottedPeers =
    spreadConnectionEndpoints(
      peers
        .slice(0, 50)
        .map((peer) => {
          const geoEnd = project(
            peer.longitude,
            peer.latitude
          );

          return {
            peer,
            geoEnd,
            end: {
              x: geoEnd.x,
              y: geoEnd.y,
            },
          };
        })
    );

  const labeledPeers = plottedPeers.slice(0, 12);
  const horizontalOrder = [...labeledPeers].sort(
    (first, second) =>
      first.end.x - second.end.x ||
      first.end.y - second.end.y
  );

  const leftCount = Math.ceil(
    horizontalOrder.length / 2
  );
  const leftPeers = horizontalOrder.slice(
    0,
    leftCount
  );
  const rightPeers = horizontalOrder.slice(
    leftCount
  );

  const labelPlacement = new Map();

  const distributeLabels = (items, align) => {
    const sorted = [...items].sort(
      (first, second) =>
        first.end.y - second.end.y
    );

    if (!sorted.length) return;

    const averageY =
      sorted.reduce(
        (total, item) => total + item.end.y,
        0
      ) / sorted.length;

    const verticalGap = 64;
    const firstY =
      averageY -
      ((sorted.length - 1) * verticalGap) / 2;

    sorted.forEach((item, index) => {
      labelPlacement.set(
        item.peer.ip,
        {
          align,
          offsetY:
            firstY +
            index * verticalGap -
            item.end.y,
        }
      );
    });
  };

  distributeLabels(leftPeers, "left");
  distributeLabels(rightPeers, "right");

  for (const item of plottedPeers) {
    const peer = item.peer;
    const geoEnd = item.geoEnd || item.end;
    const end = item.end;

    const displayOffset = Math.hypot(
      end.x - geoEnd.x,
      end.y - geoEnd.y
    );

    const dx = geoEnd.x - start.x;
    const dy = geoEnd.y - start.y;
    const distance = Math.sqrt(dx * dx + dy * dy);
    const midX = (start.x + geoEnd.x) / 2;
    const curveDirection = midX > 500 ? -1 : 1;

    const midY =
      (start.y + geoEnd.y) / 2 -
      curveDirection *
        Math.max(
          42,
          distance * 0.16
        );

    const recentClass =
      peer.active === false
        ? " recent"
        : "";
    const path = svgNode("path", {
      d: `M ${start.x.toFixed(1)} ${start.y.toFixed(1)} Q ${midX.toFixed(1)} ${midY.toFixed(1)} ${geoEnd.x.toFixed(1)} ${geoEnd.y.toFixed(1)}`,
      class: `map-link ${peer.direction || "outbound"}${recentClass}`,
      "stroke-width": Math.min(4.4, 1.8 + Math.sqrt(number(peer.connections)) * 0.5).toFixed(2),
    });
    links.appendChild(path);

    if (displayOffset > 0.75) {
      const leader = svgNode(
        "line",
        {
          x1: geoEnd.x.toFixed(1),
          y1: geoEnd.y.toFixed(1),
          x2: end.x.toFixed(1),
          y2: end.y.toFixed(1),
          class:
            `map-marker-leader` +
            recentClass,
        }
      );

      links.appendChild(leader);
    }

    const geoAnchor = svgNode(
      "circle",
      {
        cx: geoEnd.x.toFixed(1),
        cy: geoEnd.y.toFixed(1),
        r: 3.8,
        class:
          `map-geo-anchor ` +
          `${peer.direction || "outbound"}` +
          recentClass,
      }
    );

    const geoTitle = svgNode("title");

    geoTitle.textContent =
      `${peerDisplayName(peer)} · ` +
      `${locationLabel(peer)} · ` +
      "approximate GeoIP location";

    geoAnchor.appendChild(geoTitle);

    makeInsightClickable(
      geoAnchor,
      `Open details for ${peerDisplayName(peer)}`,
      () => openPeerInsight(peer)
    );

    markers.appendChild(geoAnchor);

    const marker = svgNode("circle", {
      cx: end.x.toFixed(1), cy: end.y.toFixed(1),
      r: Math.min(11, 5 + Math.sqrt(number(peer.connections))),
      class:
        `map-marker ${peer.direction || "outbound"}` +
        `${recentClass}` +
        `${
          displayOffset > 0.75
            ? " spidered"
            : ""
        }`,
      filter: "url(#markerGlow)",
    });
    const title = svgNode("title");
    const stateText = peer.active === false ? `last seen ${ageLabel(peer.seconds_since_seen)}` : "active now";
    title.textContent =
      `${peerTooltip(peer)} · ${stateText}`;
    marker.appendChild(title);

    makeInsightClickable(
      marker,
      `Open details for ${peerDisplayName(peer)}`,
      () => openPeerInsight(peer)
    );

    markers.appendChild(marker);

    focusBounds.push({
      x: geoEnd.x,
      y: geoEnd.y,
    });

    if (displayOffset > 0.75) {
      focusBounds.push({
        x: end.x,
        y: end.y,
      });
    }

    const placement = labelPlacement.get(
      peer.ip
    );

    if (placement) {
      const label = addMapLabel(
        labels,
        end.x,
        end.y,
        peerDisplayName(peer),
        peerMapDetail(peer),
        placement.align,
        peer.active === false
          ? "recent"
          : peer.direction || "outbound",
        placement.offsetY,
      );

      // Clickable map label: remote client
      label.style.pointerEvents = "all";
      label.style.cursor = "pointer";

      makeInsightClickable(
        label,
        `Open details for ${peerDisplayName(peer)}`,
        () => openPeerInsight(peer)
      );

    // Label dimensions are excluded from automatic map framing.
    }
  }

  fitConnectionMap(focusBounds);
}

function findService(snapshot, name) {
  return (snapshot.security?.services || []).find((service) => String(service.name).toLowerCase() === name.toLowerCase());
}

function findCheck(snapshot, text) {
  const needle = text.toLowerCase();
  return (snapshot.url_checks || []).find((check) => String(check.name).toLowerCase().includes(needle));
}

function findPeer(snapshot, name) {
  const needle = name.toLowerCase();
  return (snapshot.wireguard || []).find((peer) => String(peer.name || "").toLowerCase().includes(needle));
}

function topologyLink(parent, x1, y1, x2, y2, label, status = "good", dashed = false) {
  const line = svgNode("path", {
    d: `M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}`,
    class: `topology-link ${status}${dashed ? " dashed" : ""}`,
    "marker-end": "url(#topologyArrow)",
  });
  parent.appendChild(line);
  if (label) {
    const text = svgNode("text", { x: (x1 + x2) / 2, y: (y1 + y2) / 2 - 7, class: "topology-link-label" });
    text.textContent = label;
    parent.appendChild(text);
  }
}

function topologyNode(parent, options) {
  const group = svgNode("g", { class: `topology-node ${options.status || "good"}` });
  group.appendChild(svgNode("rect", { x: options.x, y: options.y, width: options.width, height: options.height, rx: 17 }));
  group.appendChild(svgNode("circle", { cx: options.x + options.width - 18, cy: options.y + 18, r: 5, class: "topology-status" }));
  const eyebrow = svgNode("text", { x: options.x + 16, y: options.y + 21, class: "topology-eyebrow" });
  eyebrow.textContent = options.eyebrow || "EDGE";
  group.appendChild(eyebrow);
  const title = svgNode("text", { x: options.x + 16, y: options.y + 47, class: "topology-title" });
  title.textContent = options.title;
  group.appendChild(title);
  const lines = Array.isArray(options.lines) ? options.lines : [];
  lines.slice(0, 3).forEach((line, index) => {
    const text = svgNode("text", { x: options.x + 16, y: options.y + 70 + index * 17, class: index === 0 ? "topology-detail" : "topology-subdetail" });
    text.textContent = line;
    group.appendChild(text);
  });
  if (options.metric) {
    const metric = svgNode("text", { x: options.x + 16, y: options.y + options.height - 15, class: "topology-metric" });
    metric.textContent = options.metric;
    group.appendChild(metric);
  }
  parent.appendChild(group);
}

function renderTopology(snapshot) {
  state.mapRenderToken += 1;
  window.EdgeWatchMapLibre?.hide();
  $("connectionMapLibre")?.classList.add("hidden");
  $("mapZoomControls")?.classList.add("hidden");

  const connections = snapshot.network?.connections || {};
  const links = $("topologyLinks");
  const nodes = $("topologyNodes");
  clear(links);
  clear(nodes);
  $("connectionMap").classList.add("hidden");
  $("topologyMap").classList.remove("hidden");
  $("mapLegend").classList.add("hidden");
  $("mapEmpty").style.display = "none";
  $("mapSummary").textContent = `${number(connections.public_connection_count)} public · ${number(connections.internal_connection_count)} internal connections`;
  $("mapNote").textContent = "The topology view uses configured service names and private paths without assigning false geographic locations.";

  const origin = connections.origin || {};
  const publicIp = origin.ip || (connections.public_interface_ips || [])[0] || "Public IP unavailable";
  const caddy = findService(snapshot, "caddy");
  const agent = findService(snapshot, "edgewatch-agent");
  const wireguardPeers = Array.isArray(snapshot.wireguard) ? snapshot.wireguard : [];
  const wgOnline = wireguardPeers.filter((peer) => peer.online).length;
  const internal = Array.isArray(connections.internal_peers) ? connections.internal_peers : [];
  const topology = snapshot.topology || {};
  const serviceDefinitions = Array.isArray(topology.services)
    ? topology.services.slice(0, 4)
    : [];

  const exactCheck = (name) => {
    const needle = String(name || "").trim().toLowerCase();
    if (!needle) return null;
    return (snapshot.url_checks || []).find(
      (check) => String(check.name || "").trim().toLowerCase() === needle
    ) || null;
  };

  const entity = (definition) => {
    const peerName = String(definition.peer_name || "").trim();
    const peer = peerName ? findPeer(snapshot, peerName) : null;
    const checks = (Array.isArray(definition.check_names) ? definition.check_names : [])
      .map(exactCheck)
      .filter(Boolean);
    const flow = peerName
      ? internal.find((item) => String(item.name || "").toLowerCase().includes(peerName.toLowerCase()))
      : null;
    const hasPeerRequirement = Boolean(peerName);
    const peerOk = !hasPeerRequirement || Boolean(peer?.online);
    const checksOk = !checks.length || checks.every((item) => item.ok);
    const checksKnown = checks.length > 0;
    const status = peerOk && checksOk
      ? "good"
      : (Boolean(peer?.online) || (checksKnown && checks.some((item) => item.ok)))
        ? "warn"
        : "bad";
    return { definition, peer, checks, flow, status };
  };

  const services = serviceDefinitions.map(entity);
  const caddyStatus = caddy?.active ? "good" : "bad";
  const agentStatus = agent?.active ? "good" : "bad";
  const wgStatus = wireguardPeers.length && wgOnline === wireguardPeers.length
    ? "good"
    : wgOnline
      ? "warn"
      : "bad";

  topologyLink(links, 205, 250, 300, 175, `${number(connections.public_connection_count)} active`, caddyStatus);
  topologyLink(links, 520, 175, 600, 235, `${number(connections.internal_connection_count)} private`, wgStatus);
  topologyLink(links, 520, 335, 600, 275, `${number(connections.local_connection_count)} loopback`, agentStatus, true);

  topologyNode(nodes, {
    x: 30, y: 190, width: 175, height: 120, status: "good", eyebrow: "PUBLIC NETWORK",
    title: "Internet clients",
    lines: [`${number(connections.public_peer_count)} unique public IPs`, `${number(connections.public_connection_count)} established TCP`],
    metric: state.flowScope === "recent" ? `${number(connections.recent_public_peer_count)} seen recently` : "Current socket sample",
  });
  topologyNode(nodes, {
    x: 300, y: 95, width: 220, height: 160, status: caddyStatus, eyebrow: "PUBLIC EDGE",
    title: "Caddy reverse proxy",
    lines: [publicIp, locationLabel(origin), caddy?.active ? "HTTPS edge healthy" : "Caddy service unavailable"],
    metric: "Ports 80 and 443",
  });
  topologyNode(nodes, {
    x: 300, y: 285, width: 220, height: 125, status: agentStatus, eyebrow: "OBSERVABILITY",
    title: "EdgeWatch agent",
    lines: [snapshot.system?.hostname || "VPS", agent?.active ? "Collector active" : "Collector service unavailable"],
    metric: `${number(connections.established)} TCP sockets classified`,
  });
  topologyNode(nodes, {
    x: 600, y: 175, width: 130, height: 135, status: wgStatus, eyebrow: "PRIVATE TUNNEL",
    title: "WireGuard",
    lines: [`${wgOnline}/${wireguardPeers.length} peers online`, `${topology.wireguard_interface || "Configured interface"} encrypted path`],
    metric: `${number(connections.internal_connection_count)} internal TCP`,
  });

  if (!services.length) {
    topologyNode(nodes, {
      x: 790, y: 190, width: 180, height: 120, status: "warn", eyebrow: "CONFIGURATION",
      title: "No service nodes",
      lines: ["Add topology_services", "to the private site config"],
      metric: "Base topology remains active",
    });
    topologyLink(links, 730, 245, 790, 250, "Configure", "warn", true);
    return;
  }

  const nodeHeight = 100;
  const top = 35;
  const available = 430;
  const gap = services.length === 1
    ? 0
    : Math.max(18, (available - services.length * nodeHeight) / (services.length - 1));

  services.forEach((service, index) => {
    const y = services.length === 1
      ? 190
      : top + index * (nodeHeight + gap);
    const firstCheck = service.checks[0] || null;
    const sourceX = service.definition.path === "edge" ? 520 : 730;
    const sourceY = service.definition.path === "edge" ? 175 : 245;
    const count = number(service.flow?.connections);
    const linkLabel = count > 0
      ? `${count} TCP`
      : String(service.definition.link_label || "Configured path");

    topologyLink(links, sourceX, sourceY, 790, y + nodeHeight / 2, linkLabel, service.status);
    topologyNode(nodes, {
      x: 790,
      y,
      width: 180,
      height: nodeHeight,
      status: service.status,
      eyebrow: service.definition.eyebrow || "SERVICE",
      title: service.definition.name || "Configured service",
      lines: [
        service.peer?.allowed_ips?.[0] || firstCheck?.url || "Configured endpoint",
        service.peer
          ? (service.peer.online ? "WireGuard online" : "WireGuard offline")
          : (firstCheck?.ok ? "Endpoint healthy" : firstCheck ? "Endpoint needs review" : "No live check configured"),
      ],
      metric: count > 0
        ? `${count} active TCP`
        : firstCheck?.latency_ms
          ? `${firstCheck.latency_ms} ms check`
          : "Configuration-driven node",
    });
  });
}

function renderMap(snapshot) {
  if (state.mapMode === "topology") {
    renderTopology(snapshot);
  } else {
    renderWorldMapPreferred(snapshot);
  }
}

function modeClass(mode) {
  const value = String(mode || "").toLowerCase();
  if (value.includes("transcode")) return "transcode";
  if (value.includes("direct")) return "good";
  return "warn";
}

/* EdgeWatch Plex artwork cards */

function ewFormatBandwidth(value) {
  const kbps = Math.max(
    0,
    number(value)
  );

  if (kbps >= 1000) {
    return `${(
      kbps / 1000
    ).toLocaleString(
      undefined,
      {
        minimumFractionDigits: 1,
        maximumFractionDigits: 1,
      }
    )} Mbps`;
  }

  return `${Math.round(
    kbps
  ).toLocaleString()} Kbps`;
}

function ewNormalizeAddress(value) {
  const address = String(
    value || ""
  )
    .replace(/^\[|\]$/g, "")
    .split("%", 1)[0];

  if (
    address
      .toLowerCase()
      .startsWith("::ffff:")
  ) {
    return address.slice(7);
  }

  return address;
}

function ewSessionPeer(
  snapshot,
  session
) {
  const address =
    ewNormalizeAddress(
      session.address
    );

  const peers = Array.isArray(
    snapshot.network
      ?.connections
      ?.public_peers
  )
    ? snapshot.network
        .connections
        .public_peers
    : [];

  return peers.find(
    (peer) =>
      ewNormalizeAddress(
        peer.ip
      ) === address
  );
}

function ewArtworkUrl(session) {
  const key = String(
    session.artwork_key || ""
  );

  if (
    !/^[0-9a-f]{64}\.(jpg|jpeg|png|webp|gif|avif)$/i.test(
      key
    )
  ) {
    return "";
  }

  return (
    "/api/v1/plex/artwork/"
    + encodeURIComponent(key)
  );
}

function ewDecision(value) {
  const normalized = String(
    value || ""
  )
    .toLowerCase()
    .replace(/[\s_-]/g, "");

  if (
    normalized === "directplay"
  ) {
    return "Direct Play";
  }

  if (
    normalized === "directstream"
  ) {
    return "Direct Stream";
  }

  if (
    normalized === "transcode"
  ) {
    return "Transcode";
  }

  return value || "Unknown";
}

function ewRemainingText(session) {
  const duration = number(
    session.duration_ms
  );

  const position = number(
    session.view_offset_ms
  );

  if (duration <= 0) {
    return "";
  }

  const remaining = Math.max(
    0,
    duration - position
  );

  const minutes = Math.ceil(
    remaining / 60000
  );

  let remainingLabel;

  if (minutes >= 60) {
    const hours = Math.floor(
      minutes / 60
    );

    const rest =
      minutes % 60;

    remainingLabel = `${hours}h${
      rest
        ? ` ${rest}m`
        : ""
    } left`;
  } else {
    remainingLabel =
      `${minutes} min left`;
  }

  const finish = new Date(
    Date.now() + remaining
  ).toLocaleTimeString(
    [],
    {
      hour: "numeric",
      minute: "2-digit",
    }
  );

  return (
    `${remainingLabel}`
    + ` · ends ${finish}`
  );
}

function ewTechnicalRow(
  label,
  primary,
  secondary
) {
  const row = node(
    "div",
    "plex-art-tech-row"
  );

  row.appendChild(
    node(
      "span",
      "",
      label
    )
  );

  const copy = node(
    "div",
    "plex-art-tech-copy"
  );

  copy.appendChild(
    node(
      "strong",
      "",
      primary || "Unavailable"
    )
  );

  if (secondary) {
    copy.appendChild(
      node(
        "small",
        "",
        secondary
      )
    );
  }

  row.appendChild(copy);

  return row;
}

function renderPlex(snapshot) {
  const plex =
    snapshot.plex || {};

  const sessions = Array.isArray(
    plex.sessions
  )
    ? plex.sessions
    : [];

  const servers = Array.isArray(
    plex.servers
  )
    ? plex.servers
    : [];

  $("streamHero").textContent =
    String(
      number(
        plex.active_streams
      )
    );

  setStatusBadge(
    $("plexServerSummary"),
    `${number(
      plex.healthy_servers
    )}/${number(
      plex.server_count
    )} servers`,
    servers.length
      && number(
        plex.healthy_servers
      ) === servers.length
      ? "good"
      : "bad"
  );

  $("plexModeSummary").textContent =
    sessions.length
      ? `${number(
          plex.direct_play
        )} direct play · ${number(
          plex.direct_stream
        )} direct stream · ${number(
          plex.transcode
        )} transcode`
      : "No streams";

  const summary =
    $("streamSummary");

  clear(summary);

  for (
    const [label, value]
    of [
      [
        "Streams",
        number(
          plex.active_streams
        ),
      ],
      [
        "Direct play",
        number(
          plex.direct_play
        ),
      ],
      [
        "Direct stream",
        number(
          plex.direct_stream
        ),
      ],
      [
        "Transcodes",
        number(
          plex.transcode
        ),
      ],
      [
        "Estimated bandwidth",
        ewFormatBandwidth(
          plex.bandwidth_kbps
        ),
      ],
    ]
  ) {
    const item = node(
      label === "Streams" ? "button" : "div",
      label === "Streams" ? "stream-stat metric-list-card stream-client-summary-card" : "stream-stat"
    );

    if (label === "Streams") {
      item.type = "button";
      item.setAttribute("aria-label", "View all active Plex stream clients");
      item.title = "View all active Plex stream clients";
      item.addEventListener("click", () => openStreamClientsDrawer(snapshot));
    }

    item.appendChild(
      node(
        "span",
        "",
        label
      )
    );

    item.appendChild(
      node(
        "strong",
        "",
        value
      )
    );

    summary.appendChild(item);
  }

  const grid =
    $("streamGrid");

  clear(grid);

  if (!sessions.length) {
    grid.appendChild(
      node(
        "div",
        "empty-state",
        "No Plex streams are "
        + "active right now."
      )
    );

    return;
  }

  for (
    const session of sessions
  ) {
    const artwork =
      ewArtworkUrl(session);

    const peer =
      ewSessionPeer(
        snapshot,
        session
      );

    const card = node(
      "article",
      "plex-art-card"
    );

    if (artwork) {
      const backdrop =
        document.createElement(
          "img"
        );

      backdrop.className =
        "plex-art-backdrop";

      backdrop.src =
        artwork;

      backdrop.alt = "";

      backdrop.loading =
        "lazy";

      backdrop.decoding =
        "async";

      backdrop.setAttribute(
        "aria-hidden",
        "true"
      );

      backdrop.addEventListener(
        "error",
        () => backdrop.remove()
      );

      card.appendChild(
        backdrop
      );
    }

    card.appendChild(
      node(
        "div",
        "plex-art-scrim"
      )
    );

    const content = node(
      "div",
      "plex-art-content"
    );

    const header = node(
      "div",
      "plex-art-head"
    );

    const posterWrap = node(
      "div",
      "plex-art-poster-wrap"
    );

    posterWrap.appendChild(
      node(
        "div",
        "plex-art-fallback",
        String(
          session.title || "?"
        )
          .slice(0, 1)
          .toUpperCase()
      )
    );

    if (artwork) {
      const poster =
        document.createElement(
          "img"
        );

      poster.className =
        "plex-art-poster";

      poster.src =
        artwork;

      poster.alt =
        `${
          session.title || "Plex"
        } artwork`;

      poster.loading =
        "lazy";

      poster.decoding =
        "async";

      poster.addEventListener(
        "load",
        () =>
          posterWrap.classList.add(
            "has-art"
          )
      );

      poster.addEventListener(
        "error",
        () => poster.remove()
      );

      posterWrap.appendChild(
        poster
      );
    }

    header.appendChild(
      posterWrap
    );

    const title = node(
      "div",
      "plex-art-title"
    );

    title.appendChild(
      node(
        "strong",
        "",
        session.title
          || "Untitled media"
      )
    );

    title.appendChild(
      node(
        "span",
        "",
        session.subtitle
          || session.media_type
          || "Plex media"
      )
    );

    const remaining =
      ewRemainingText(
        session
      );

    if (remaining) {
      title.appendChild(
        node(
          "small",
          "",
          remaining
        )
      );
    }

    header.appendChild(
      title
    );

    header.appendChild(
      node(
        "span",
        `mode-pill ${modeClass(
          session.mode
        )}`,
        session.mode
          || "Unknown"
      )
    );

    content.appendChild(
      header
    );

    const progress = node(
      "div",
      "plex-art-progress"
    );

    const fill =
      node("i");

    fill.style.width =
      `${Math.max(
        0,
        Math.min(
          100,
          number(
            session
              .progress_percent
          )
        )
      )}%`;

    progress.appendChild(
      fill
    );

    content.appendChild(
      progress
    );

    const technical = node(
      "div",
      "plex-art-tech"
    );

    technical.appendChild(
      ewTechnicalRow(
        "Source",
        session.source,
        [
          `Video ${ewDecision(
            session
              .video_decision
          )}`,
          `Audio ${ewDecision(
            session
              .audio_decision
          )}`,
        ].join(" · ")
      )
    );

    technical.appendChild(
      ewTechnicalRow(
        "Output",
        session.output,
        `${number(
          session
            .progress_percent
        ).toFixed(0)}% complete`
      )
    );

    content.appendChild(
      technical
    );

    const footer = node(
      "div",
      "plex-art-footer"
    );

    footer.appendChild(
      node(
        "div",
        "plex-art-user",
        String(
          session.user || "?"
        )
          .slice(0, 1)
          .toUpperCase()
      )
    );

    const viewer = node(
      "div",
      "plex-art-user-copy"
    );

    viewer.appendChild(
      node(
        "strong",
        "",
        session.user
          || "Unknown viewer"
      )
    );

    viewer.appendChild(
      node(
        "span",
        "",
        `${session.server || "Plex"}`
        + ` → ${
          session.player
          || "Unknown player"
        }`
      )
    );

    const address =
      ewNormalizeAddress(
        session.address
      );

    let location = "";

    if (peer) {
      location =
        locationLabel(peer);
    } else if (
      session.location === "lan"
    ) {
      location =
        "Local network";
    } else if (
      session.location === "wan"
    ) {
      location =
        "Remote";
    } else {
      location =
        session.location || "";
    }

    viewer.appendChild(
      node(
        "small",
        "",
        [
          location,
          address,
        ]
          .filter(Boolean)
          .join(" · ")
      )
    );

    footer.appendChild(
      viewer
    );

    const bandwidth = node(
      "div",
      "plex-art-bandwidth"
    );

    bandwidth.appendChild(
      node(
        "strong",
        "",
        ewFormatBandwidth(
          session
            .bandwidth_kbps
        )
      )
    );

    bandwidth.appendChild(
      node(
        "span",
        "",
        session.state
          || "playing"
      )
    );

    footer.appendChild(
      bandwidth
    );

    content.appendChild(
      footer
    );

    card.appendChild(
      content
    );

    grid.appendChild(
      card
    );
  }
}

function controlCard(name, value, ok, detail = "") {
  const card = node("article", `control-card ${ok === true ? "good" : ok === false ? "bad" : "warn"}`);
  const top = node("div", "control-top");
  top.appendChild(node("strong", "", name));
  top.appendChild(node("span", `health-dot${ok === true ? "" : ok === false ? " bad" : " warn"}`));
  card.appendChild(top);
  card.appendChild(node("span", "", value));
  if (detail) card.appendChild(node("small", "", detail));
  return card;
}

// EdgeWatch clickable firewall rules

function firewallAddressList(addresses) {
  const rows = [];

  for (const family of [
    ["IPv4", addresses?.ipv4],
    ["IPv6", addresses?.ipv6],
  ]) {
    const values =
      Array.isArray(family[1])
        ? family[1]
        : [];

    if (values.length) {
      rows.push(
        `${family[0]}: ${values.join(", ")}`
      );
    }
  }

  return rows.join("\n");
}

function firewallRuleCard({
  title,
  action,
  protocol,
  ports,
  source,
  destination,
  ipVersion,
}) {
  const card = node(
    "article",
    "firewall-rule-card"
  );

  const header = node(
    "div",
    "firewall-rule-header"
  );

  header.appendChild(
    node(
      "strong",
      "",
      title || "Firewall rule"
    )
  );

  if (action) {
    header.appendChild(
      node(
        "span",
        `firewall-action ${
          String(action)
            .toLowerCase()
            .includes("accept") ||
          String(action)
            .toLowerCase()
            .includes("allow")
            ? "allow"
            : "block"
        }`,
        action
      )
    );
  }

  card.appendChild(header);

  const grid = node(
    "div",
    "insight-kv-grid firewall-rule-grid"
  );

  for (const [label, value] of [
    ["Protocol", protocol],
    ["Ports", ports],
    ["Destination", destination],
    ["Source", source],
    ["Address family", ipVersion],
  ]) {
    const row = insightRow(label, value);

    if (row) {
      grid.appendChild(row);
    }
  }

  card.appendChild(grid);

  return card;
}

function openUfwFirewallDrawer(snapshot) {
  const firewall =
    snapshot?.security?.firewall || {};

  const rules =
    Array.isArray(firewall.rules)
      ? firewall.rules
      : [];

  showInsightDrawer({
    eyebrow: "HOST FIREWALL",
    title: "UFW host firewall",
    subtitle:
      firewall.active
        ? "Active · local VPS policy"
        : "Inactive or unavailable",

    render(body) {
      const stats = node(
        "div",
        "metric-detail-grid firewall-summary-grid"
      );

      stats.appendChild(
        insightStat(
          "Status",
          firewall.active
            ? "Active"
            : "Inactive"
        )
      );

      stats.appendChild(
        insightStat(
          "Configured rules",
          number(firewall.rule_count)
        )
      );

      stats.appendChild(
        insightStat(
          "Available",
          firewall.available
            ? "Yes"
            : "No"
        )
      );

      body.appendChild(stats);

      body.appendChild(
        insightSection("Default policy")
      );

      body.appendChild(
        node(
          "div",
          "metric-detail-note",
          firewall.default_policy ||
            "No default-policy information was reported."
        )
      );

      body.appendChild(
        insightSection("Configured rules")
      );

      const list = node(
        "div",
        "firewall-rule-list"
      );

      if (!rules.length) {
        list.appendChild(
          node(
            "div",
            "metric-detail-note",
            firewall.rule_detail ||
              "No numbered UFW rules were reported in the current snapshot."
          )
        );
      }

      for (const rule of rules) {
        list.appendChild(
          firewallRuleCard({
            title:
              `Rule ${number(rule.number)}`,
            action: rule.action,
            destination:
              rule.destination,
            source: rule.source,
            ipVersion:
              rule.ip_version,
          })
        );
      }

      body.appendChild(list);

      body.appendChild(
        node(
          "div",
          "metric-detail-note",
          "This view is read-only. EdgeWatch does not add, remove, or modify UFW rules."
        )
      );
    },
  });
}

function openLinodeFirewallDrawer(snapshot) {
  const firewall =
    snapshot?.linode_firewall || {};

  const inbound =
    Array.isArray(firewall.inbound_rules)
      ? firewall.inbound_rules
      : [];

  const outbound =
    Array.isArray(firewall.outbound_rules)
      ? firewall.outbound_rules
      : [];

  showInsightDrawer({
    eyebrow: "CLOUD FIREWALL",
    title:
      firewall.label ||
      "Linode Cloud Firewall",

    subtitle: [
      firewall.status,
      firewall.attached
        ? "Attached to VPS"
        : "Not attached",
    ]
      .filter(Boolean)
      .join(" · "),

    render(body) {
      const stats = node(
        "div",
        "metric-detail-grid firewall-summary-grid"
      );

      for (const [label, value] of [
        [
          "Attached",
          firewall.attached
            ? "Yes"
            : "No",
        ],
        [
          "Inbound policy",
          firewall.inbound_policy ||
            "Unknown",
        ],
        [
          "Outbound policy",
          firewall.outbound_policy ||
            "Unknown",
        ],
        [
          "Inbound rules",
          number(
            firewall.inbound_rule_count
          ),
        ],
        [
          "Outbound rules",
          number(
            firewall.outbound_rule_count
          ),
        ],
      ]) {
        stats.appendChild(
          insightStat(label, value)
        );
      }

      body.appendChild(stats);

      body.appendChild(
        insightSection("Inbound rules")
      );

      const inboundList = node(
        "div",
        "firewall-rule-list"
      );

      if (!inbound.length) {
        inboundList.appendChild(
          node(
            "div",
            "metric-detail-note",
            "No explicit inbound rules are configured. The default inbound policy applies."
          )
        );
      }

      for (const rule of inbound) {
        inboundList.appendChild(
          firewallRuleCard({
            title:
              rule.label ||
              "Inbound rule",
            action: rule.action,
            protocol: rule.protocol,
            ports: rule.ports,
            source:
              firewallAddressList(
                rule.addresses
              ),
          })
        );
      }

      body.appendChild(inboundList);

      body.appendChild(
        insightSection("Outbound rules")
      );

      const outboundList = node(
        "div",
        "firewall-rule-list"
      );

      if (!outbound.length) {
        outboundList.appendChild(
          node(
            "div",
            "metric-detail-note",
            `No explicit outbound rules are configured. Default outbound policy: ${
              firewall.outbound_policy ||
              "unknown"
            }.`
          )
        );
      }

      for (const rule of outbound) {
        outboundList.appendChild(
          firewallRuleCard({
            title:
              rule.label ||
              "Outbound rule",
            action: rule.action,
            protocol: rule.protocol,
            ports: rule.ports,
            source:
              firewallAddressList(
                rule.addresses
              ),
          })
        );
      }

      body.appendChild(outboundList);

      body.appendChild(
        node(
          "div",
          "metric-detail-note",
          "This is a read-only view of the Linode Cloud Firewall. EdgeWatch does not change cloud firewall rules."
        )
      );
    },
  });
}

function renderControls(snapshot) {
  const security = snapshot.security || {};
  const sshd = security.sshd || {};
  const linode = snapshot.linode_firewall || {};
  const geoip = snapshot.geoip || {};
  const notifications = snapshot.notifications || {};
  const endpoints = snapshot.url_checks || [];
  const expiring = endpoints.filter((item) => {
    const daysRemaining = item?.certificate?.days_remaining;
    return daysRemaining !== null
      && daysRemaining !== undefined
      && number(daysRemaining) <= number(item?.certificate_warn_days, 21);
  });
  const controls = [
    controlCard("UFW host firewall", security.firewall?.active ? "Active" : "Inactive", Boolean(security.firewall?.active), security.firewall?.detail || "Host policy"),
    controlCard("Linode Cloud Firewall", !linode.enabled ? "Not enabled" : linode.ok ? "Verified and attached" : "Needs attention", !linode.enabled ? null : Boolean(linode.ok), linode.enabled ? `${linode.status || "unknown"} · attached ${linode.attached ? "yes" : "no"}` : "Optional read-only check"),
    controlCard("SSH passwords", sshd.available ? (sshd.password_authentication === "no" ? "Disabled" : "Enabled") : "Unknown", sshd.available ? sshd.password_authentication === "no" : null, "Effective sshd configuration"),
    controlCard("SSH root login", sshd.available ? String(sshd.permit_root_login || "unknown") : "Unknown", sshd.available ? sshd.permit_root_login === "no" : null, "Direct root access"),
    controlCard("AppArmor", security.apparmor?.active ? "Active" : "Inactive", Boolean(security.apparmor?.active), security.apparmor?.profiles ? `${security.apparmor.profiles} loaded profiles` : "Mandatory access control"),
    controlCard("Automatic updates", security.automatic_updates?.ok ? "Timer healthy" : "Needs review", Boolean(security.automatic_updates?.ok), `${number(security.pending_updates)} pending packages`),
    controlCard("Time synchronization", security.time_sync?.synchronized ? "Synchronized" : "Not synchronized", Boolean(security.time_sync?.synchronized), "TLS and event timeline integrity"),
    controlCard("Service journal", security.service_journal?.warning_count ? `${security.service_journal.warning_count} warnings` : "Quiet", !security.service_journal?.warning_count, "Last 15 minutes"),
    controlCard("Fail2ban", !security.fail2ban?.installed ? "Not installed" : security.fail2ban?.active ? "Active" : "Inactive", !security.fail2ban?.installed ? null : Boolean(security.fail2ban?.active), (security.fail2ban?.jails || []).join(", ") || "Optional secondary control"),
    controlCard("Local GeoIP", geoip.city_available ? "Map ready" : "Database missing", geoip.city_available ? true : null, "Connection IPs stay on the VPS"),
    controlCard("Push notifications", notifications.configured ? "Configured" : notifications.enabled ? "Incomplete" : "Disabled", notifications.configured ? true : notifications.enabled ? false : null, notifications.minimum_severity ? `Minimum ${notifications.minimum_severity}` : "ntfy support"),
    controlCard("TLS certificates", expiring.length ? `${expiring.length} expiring` : "Healthy", expiring.length === 0, `${endpoints.filter((item) => item.certificate?.available).length} certificates observed`),
    controlCard("Failed systemd units", security.failed_units?.length ? `${security.failed_units.length} failed` : "None", !(security.failed_units?.length), (security.failed_units || []).slice(0, 2).join(", ") || "System unit state"),
    controlCard("Kernel network baseline", security.kernel?.ok ? "Aligned" : "Differences found", Boolean(security.kernel?.ok), "Reviewed sysctl controls"),
  ];
  controls[0].classList.add(
    "control-card-link"
  );

  makeInsightClickable(
    controls[0],
    "Open UFW firewall rules",
    () => openUfwFirewallDrawer(snapshot)
  );

  controls[1].classList.add(
    "control-card-link"
  );

  makeInsightClickable(
    controls[1],
    "Open Linode Cloud Firewall rules",
    () => openLinodeFirewallDrawer(snapshot)
  );

  const grid = $("controlGrid");
  clear(grid);
  controls.forEach((card) => grid.appendChild(card));
  const healthy = controls.filter((card) => card.classList.contains("good")).length;
  setStatusBadge($("protectionSummary"), `${healthy}/${controls.length} healthy`, healthy >= controls.length - 2 ? "good" : healthy >= controls.length / 2 ? "warn" : "bad");
}

function renderLinode(snapshot) {
  const firewall = snapshot.linode_firewall || {};
  const container = $("linodeCard");
  clear(container);
  if (!firewall.enabled) {
    setStatusBadge($("linodeSummary"), "Optional", "warn");
    container.appendChild(node("div", "empty-state", "Add a read-only Linode API token and firewall ID to verify the cloud edge policy."));
    return;
  }
  setStatusBadge($("linodeSummary"), firewall.ok ? "Verified" : "Needs attention", firewall.ok ? "good" : "bad");
  const card = node("article", "cloud-card");
  card.appendChild(node("h3", "", firewall.label || `Firewall ${firewall.id || ""}`));
  card.appendChild(node("p", "", firewall.status || "Unknown status"));
  const metrics = node("div", "cloud-metrics");
  for (const [label, value] of [
    ["Attached to VPS", firewall.attached ? "Yes" : "No"],
    ["Inbound policy", firewall.inbound_policy || "unknown"],
    ["Outbound policy", firewall.outbound_policy || "unknown"],
    ["Inbound rules", number(firewall.inbound_rule_count)],
    ["Outbound rules", number(firewall.outbound_rule_count)],
  ]) {
    const item = node("div");
    item.appendChild(node("span", "", label));
    item.appendChild(node("strong", "", value));
    metrics.appendChild(item);
  }
  card.appendChild(metrics);

  card.classList.add(
    "cloud-card-link"
  );

  makeInsightClickable(
    card,
    "Open Linode Cloud Firewall rules",
    () =>
      openLinodeFirewallDrawer(
        snapshot
      )
  );

  container.appendChild(card);
}

// EdgeWatch clickable security events

function securityEventText(...values) {
  for (const value of values) {
    if (
      typeof value === "string" &&
      value.trim()
    ) {
      return value.trim();
    }
  }

  return "";
}

function normalizeSecurityEventText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function securityFindingCandidates(snapshot) {
  const candidates = [];

  for (const source of [
    snapshot?.findings,
    snapshot?.security?.findings,
    snapshot?.posture?.insights,
    snapshot?.posture?.findings,
    snapshot?.security_posture?.findings,
    snapshot?.security?.active_findings,
  ]) {
    if (Array.isArray(source)) {
      candidates.push(...source);
    } else if (
      source &&
      typeof source === "object"
    ) {
      candidates.push(
        ...Object.values(source).filter(
          (value) =>
            value &&
            typeof value === "object"
        )
      );
    }
  }

  return candidates;
}

function matchingSecurityFinding(event) {
  const findings = securityFindingCandidates(
    state.snapshot || {}
  );

  const fingerprint = String(event?.fingerprint || "");
  if (fingerprint) {
    const exact = findings.find(
      (finding) => String(finding?.fingerprint || "") === fingerprint
    );
    if (exact) return exact;
  }

  const eventTitle = normalizeSecurityEventText(
    event?.title
  );

  if (!eventTitle) {
    return null;
  }

  let partialMatch = null;

  for (const finding of findings) {
    const findingTitle =
      normalizeSecurityEventText(
        securityEventText(
          finding?.title,
          finding?.name,
          finding?.summary
        )
      );

    if (!findingTitle) {
      continue;
    }

    if (findingTitle === eventTitle) {
      return finding;
    }

    if (
      findingTitle.includes(eventTitle) ||
      eventTitle.includes(findingTitle)
    ) {
      partialMatch ||= finding;
    }
  }

  return partialMatch;
}

function securityEventFallbackAction(event) {
  const title = normalizeSecurityEventText(
    event?.title
  );

  if (
    title.includes("direct ssh root login")
  ) {
    return (
      "Use an administrative account with sudo " +
      "and set PermitRootLogin no."
    );
  }

  if (
    title.includes(
      "ssh password authentication"
    )
  ) {
    return (
      "Install and test SSH key authentication " +
      "for the administrative account, then set " +
      "PasswordAuthentication no."
    );
  }

  if (
    title.includes("ubuntu updates") ||
    title.includes("package updates")
  ) {
    return (
      "Review the pending packages, apply the " +
      "appropriate Ubuntu updates, and reboot if " +
      "the updated packages require it."
    );
  }

  if (
    title.includes("service warnings")
  ) {
    return (
      "Review the affected service logs and confirm " +
      "that EdgeWatch, Caddy, SSH, and WireGuard are " +
      "operating normally."
    );
  }

  return (
    "Review the event details and check Findings and " +
    "actions for the current security status."
  );
}

// EdgeWatch structured service journal details

function parseSecurityJournalDetail(detail) {
  const text = String(detail || "");
  const marker = "\n\nJournal samples:\n";
  const markerIndex = text.indexOf(marker);

  if (markerIndex < 0) {
    return {
      summary: text,
      samples: [],
    };
  }

  const summary = text
    .slice(0, markerIndex)
    .trim();

  const payload = text
    .slice(markerIndex + marker.length)
    .trim();

  const samples = payload
    .split(/\n\s*\n/)
    .map((block) => {
      const service =
        block.match(
          /^Service:\s*(.+)$/m
        )?.[1]?.trim() || "unknown";

      const timestamp =
        block.match(
          /^Timestamp:\s*(.+)$/m
        )?.[1]?.trim() || "";

      const message =
        block.match(
          /^Message:\s*([\s\S]+)$/m
        )?.[1]?.trim() || "";

      return {
        service,
        timestamp,
        message,
      };
    })
    .filter((sample) => sample.message);

  return {
    summary,
    samples,
  };
}

function securityJournalTime(value) {
  if (!value) {
    return "Unknown time";
  }

  const parsed = new Date(value);

  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "medium",
  });
}

function eventDetailStat(label, value) {
  const item = node(
    "div",
    "event-detail-stat"
  );

  item.appendChild(
    node("span", "", label)
  );

  item.appendChild(
    node("strong", "", value)
  );

  return item;
}

// EdgeWatch enhanced timeline finding details

function activeFindingForSecurityEvent(
  event,
  snapshot
) {
  const existing =
    matchingSecurityFinding(event);

  if (existing) {
    return existing;
  }

  const eventTitle =
    normalizeSecurityEventText(
      event?.title
    );

  const sources = [
    snapshot?.posture?.insights,
    snapshot?.posture?.findings,
    snapshot?.security_posture?.insights,
    snapshot?.security_posture?.findings,
    snapshot?.security?.insights,
    snapshot?.security?.findings,
    snapshot?.security?.active_findings,
    snapshot?.findings,
  ];

  for (const source of sources) {
    if (!Array.isArray(source)) {
      continue;
    }

    for (const finding of source) {
      const findingTitle =
        normalizeSecurityEventText(
          finding?.title ||
          finding?.name ||
          finding?.summary
        );

      if (
        findingTitle &&
        (
          findingTitle === eventTitle ||
          findingTitle.includes(eventTitle) ||
          eventTitle.includes(findingTitle)
        )
      ) {
        return finding;
      }
    }
  }

  return null;
}

function openSecurityEventDrawer(event) {

  const currentFinding =
    activeFindingForSecurityEvent(
      event,
      state.snapshot || {}
    );

  if (currentFinding) {
    openSecurityFindingDrawer(
      currentFinding,
      state.snapshot || {}
    );

    return;
  }

  const drawer = $("metricDrawer");
  const backdrop = $("metricDrawerBackdrop");
  const title = $("metricDrawerTitle");
  const subtitle = $("metricDrawerSubtitle");
  const body = $("metricDrawerBody");

  if (
    !drawer ||
    !backdrop ||
    !title ||
    !subtitle ||
    !body
  ) {
    return;
  }

  const finding = matchingSecurityFinding(event);
  const severity = securityEventText(
    event?.severity,
    finding?.severity,
    "info"
  );

  const detail = securityEventText(
    event?.detail,
    event?.description,
    finding?.detail,
    finding?.description,
    "No additional event detail was recorded."
  );

  const journalDetail =
    parseSecurityJournalDetail(detail);

  const action = securityEventText(
    event?.action,
    event?.recommendation,
    event?.remediation,
    finding?.action,
    finding?.recommendation,
    finding?.remediation,
    securityEventFallbackAction(event)
  );

  title.textContent =
    event?.title || "Security event";

  subtitle.textContent =
    "Recorded security event";

  clear(body);

  const grid = node(
    "div",
    "event-detail-grid"
  );

  grid.appendChild(
    eventDetailStat(
      "Severity",
      severity.toUpperCase()
    )
  );

  grid.appendChild(
    eventDetailStat(
      "Recorded",
      timeLabel(event?.ts)
    )
  );

  grid.appendChild(
    eventDetailStat(
      "Current match",
      finding
        ? "Active finding found"
        : "Historical event"
    )
  );

  body.appendChild(grid);

  const detailSection = node(
    "section",
    "event-detail-section"
  );

  detailSection.appendChild(
    node("h3", "", "Event detail")
  );

  detailSection.appendChild(
    node(
      "p",
      "",
      journalDetail.summary
    )
  );

  body.appendChild(detailSection);

  if (journalDetail.samples.length) {
    const journalSection = node(
      "section",
      "event-detail-section"
    );

    journalSection.appendChild(
      node("h3", "", "Journal entries")
    );

    const journalList = node(
      "div",
      "event-journal-list"
    );

    for (
      const sample of journalDetail.samples
    ) {
      const entry = node(
        "article",
        "event-journal-entry"
      );

      const metadata = node(
        "div",
        "event-journal-meta"
      );

      metadata.appendChild(
        node(
          "strong",
          "",
          sample.service
        )
      );

      metadata.appendChild(
        node(
          "time",
          "",
          securityJournalTime(
            sample.timestamp
          )
        )
      );

      entry.appendChild(metadata);

      entry.appendChild(
        node(
          "pre",
          "event-journal-message",
          sample.message
        )
      );

      journalList.appendChild(entry);
    }

    journalSection.appendChild(journalList);
    body.appendChild(journalSection);
  }

  const actionSection = node(
    "section",
    "event-detail-section event-detail-action"
  );

  actionSection.appendChild(
    node("h3", "", "Recommended action")
  );

  actionSection.appendChild(
    node("p", "", action)
  );

  body.appendChild(actionSection);

  if (!finding) {
    body.appendChild(
      node(
        "div",
        "metric-detail-note",
        "This is a historical timeline entry.  The issue may already be resolved.  Findings and actions shows the current state."
      )
    );
  }

  drawer.hidden = false;
  backdrop.hidden = false;

  drawer.setAttribute(
    "aria-hidden",
    "false"
  );

  document.body.classList.add(
    "metric-drawer-open"
  );

  window.requestAnimationFrame(() => {
    backdrop.classList.add("open");
    drawer.classList.add("open");
  });
}


function renderAcknowledgedFindings(snapshot) {
  const panel = $("acknowledgedPanel");
  const list = $("acknowledgedList");
  const summary = $("acknowledgedSummary");
  if (!panel || !list || !summary) return;

  const acknowledged = Array.isArray(snapshot.acknowledged_findings)
    ? snapshot.acknowledged_findings
    : activeFindingInsights(snapshot).filter((item) => item.acknowledged);

  panel.hidden = acknowledged.length === 0;
  summary.textContent = `${acknowledged.length} muted`;
  clear(list);

  for (const row of acknowledged) {
    const current = activeFindingInsights(snapshot).find(
      (item) => String(item.fingerprint || "") === String(row.fingerprint || "")
    ) || { ...row, acknowledged: true, acknowledgement: row };

    const card = node(
      "article",
      `acknowledged-card ${current.severity || "info"}`
    );

    const header = node("div", "acknowledged-card-head");
    const heading = node("div", "acknowledged-card-heading");
    heading.appendChild(node("span", "severity-pill " + (current.severity || "info"), current.severity || "info"));
    heading.appendChild(node("h3", "", current.title || "Acknowledged finding"));
    header.appendChild(heading);
    header.appendChild(node("span", "acknowledged-chip", "Notifications muted"));
    card.appendChild(header);

    card.appendChild(node("p", "acknowledged-detail", current.detail || ""));

    const meta = node("div", "acknowledged-meta");
    meta.appendChild(
      node("span", "", `Acknowledged by ${current.acknowledgement?.acknowledged_by || row.acknowledged_by || "Unknown user"}`)
    );
    meta.appendChild(
      node("span", "", findingAcknowledgementTime(
        current.acknowledgement?.acknowledged_at || row.acknowledged_at
      ))
    );
    meta.appendChild(node("span", "", current.category || "General"));
    card.appendChild(meta);

    const actions = node("div", "acknowledged-card-actions");
    const details = node("button", "secondary-action-button", "View finding");
    details.type = "button";
    details.addEventListener("click", () => openSecurityFindingDrawer(current, snapshot));
    actions.appendChild(details);
    actions.appendChild(findingAcknowledgementControl(current, { compact: true }));
    card.appendChild(actions);
    list.appendChild(card);
  }
}

function renderEvents(snapshot) {
  const events = Array.isArray(snapshot.events)
    ? snapshot.events
    : [];

  const list = $("eventList");
  clear(list);

  if (!events.length) {
    list.appendChild(
      node(
        "div",
        "empty-state",
        "No security events have been recorded."
      )
    );

    return;
  }

  for (const event of events.slice(0, 40)) {
    const item = node(
      "article",
      "event-item event-link"
    );

    item.setAttribute("role", "button");
    item.setAttribute("tabindex", "0");

    item.setAttribute(
      "aria-label",
      `Open details for ${
        event.title || "security event"
      }`
    );

    item.setAttribute(
      "title",
      "Open event details"
    );

    const openEvent = () =>
      openSecurityEventDrawer(event);

    item.addEventListener(
      "click",
      openEvent
    );

    item.addEventListener(
      "keydown",
      (keyboardEvent) => {
        if (
          keyboardEvent.key === "Enter" ||
          keyboardEvent.key === " "
        ) {
          keyboardEvent.preventDefault();
          openEvent();
        }
      }
    );

    item.appendChild(
      node(
        "div",
        "event-time",
        timeLabel(event.ts)
      )
    );

    item.appendChild(
      node(
        "span",
        `severity-pill ${
          event.severity || "info"
        }`,
        event.severity || "info"
      )
    );

    const copy = node(
      "div",
      "event-copy"
    );

    copy.appendChild(
      node(
        "strong",
        "",
        event.title || "Event"
      )
    );

    copy.appendChild(
      node(
        "small",
        "",
        event.detail || ""
      )
    );

    item.appendChild(copy);
    list.appendChild(item);
  }
}

function renderSnapshot(snapshot) {
  state.snapshot = snapshot;
  state.lastLiveAt = Date.now();
  $("recentScopeButton").textContent = `Last ${number(snapshot.network?.connections?.flow_recent_seconds, 60)}s`;
  renderPosture(snapshot);
  renderSystem(snapshot);
  renderTraffic(snapshot);
  renderMap(snapshot);
  renderFlows(snapshot);
  renderPlex(snapshot);
  renderControls(snapshot);
  renderServices(snapshot);
  renderPeers(snapshot);
  renderSecurity(snapshot);
  renderLinode(snapshot);
  renderAcknowledgedFindings(snapshot);
  renderEvents(snapshot);
  const alerts = snapshot.notifications || {};
  $("alertHero").textContent = alerts.configured ? "On" : "Off";
  const generated = new Date(snapshot.generated_at);
  $("lastUpdated").textContent = `Updated ${generated.toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" })}`;
  $("liveLabel").textContent = "Live";
  $("footerStatus").textContent = `Collector current · ${snapshot.display_timezone || "UTC"}`;
}

function chartSeries(points, key) {
  return points.map((point) => Math.max(0, number(point[key])));
}

function drawChart() {
  const canvas = $("trafficChart");
  const rect = canvas.getBoundingClientRect();
  const dpr = Math.max(1, window.devicePixelRatio || 1);
  const width = Math.max(320, Math.round(rect.width * dpr));
  const height = Math.max(120, Math.round(rect.height * dpr));
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
  }
  const context = canvas.getContext("2d");
  context.clearRect(0, 0, width, height);
  const points = state.history;
  if (points.length < 2) return;
  const rx = chartSeries(points, "rx_bps");
  const tx = chartSeries(points, "tx_bps");
  const maxValue = Math.max(1, ...rx, ...tx) * 1.12;
  const pad = 7 * dpr;
  const chartWidth = width - pad * 2;
  const chartHeight = height - pad * 2;
  context.lineWidth = dpr;
  context.strokeStyle = "rgba(148,163,184,.11)";
  for (let i = 1; i < 4; i += 1) {
    const y = pad + chartHeight * (i / 4);
    context.beginPath(); context.moveTo(pad, y); context.lineTo(width - pad, y); context.stroke();
  }
  const path = (values) => {
    context.beginPath();
    values.forEach((value, index) => {
      const x = pad + chartWidth * (index / Math.max(1, values.length - 1));
      const y = pad + chartHeight * (1 - value / maxValue);
      if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
    });
  };
  const gradient = context.createLinearGradient(0, pad, 0, height);
  gradient.addColorStop(0, "rgba(56,189,248,.20)");
  gradient.addColorStop(1, "rgba(56,189,248,0)");
  path(rx); context.lineTo(width - pad, height - pad); context.lineTo(pad, height - pad); context.closePath(); context.fillStyle = gradient; context.fill();
  path(rx); context.strokeStyle = "#38bdf8"; context.lineWidth = 2 * dpr; context.lineJoin = "round"; context.lineCap = "round"; context.stroke();
  path(tx); context.strokeStyle = "#818cf8"; context.stroke();
}

async function fetchJSON(url) {
  const response = await fetch(url, { cache: "no-store", credentials: "same-origin" });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function refreshSnapshot(showMessage = false) {
  try {
    renderSnapshot(await fetchJSON("/api/v1/snapshot"));
    if (showMessage) showToast("Dashboard refreshed");
  } catch (error) {
    $("liveLabel").textContent = "Degraded";
    $("footerStatus").textContent = `Collector unavailable · ${error.message}`;
    if (showMessage) showToast("Refresh failed");
  }
}

async function refreshHistory() {
  try {
    const data = await fetchJSON(`/api/v1/history?minutes=${state.historyMinutes}&points=1440`);
    state.history = data.points || [];
    window.cancelAnimationFrame(state.chartFrame);
    state.chartFrame = window.requestAnimationFrame(drawChart);
  } catch (error) {
    console.error("History refresh failed", error);
  }
}

function connectLive() {
  if (!("EventSource" in window)) return;
  if (state.eventSource) state.eventSource.close();
  const source = new EventSource("/api/v1/live", { withCredentials: true });
  state.eventSource = source;
  source.addEventListener("snapshot", (event) => {
    try { renderSnapshot(JSON.parse(event.data)); } catch (error) { console.error("Live snapshot parse failed", error); }
  });
  source.addEventListener("waiting", () => { $("liveLabel").textContent = "Waiting"; });
  source.addEventListener("degraded", () => { $("liveLabel").textContent = "Degraded"; });
  source.onerror = () => { $("liveLabel").textContent = "Reconnecting"; };
}

function start() {
  $("refreshButton").addEventListener("click", async () => {
    await Promise.all([refreshSnapshot(true), refreshHistory()]);
  });
  $("historyRange").addEventListener("change", (event) => {
    state.historyMinutes = number(event.target.value, 60);
    refreshHistory();
  });
  $("mapModeControl").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-map-mode]");
    if (!button) return;
    state.mapMode = button.dataset.mapMode;
    $("mapModeControl").querySelectorAll("button").forEach((item) => {
      const selected = item === button;
      item.classList.toggle("active", selected);
      item.setAttribute("aria-pressed", String(selected));
    });
    if (state.snapshot) renderMap(state.snapshot);
  });
  $("flowScopeControl").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-flow-scope]");
    if (!button) return;
    state.flowScope = button.dataset.flowScope;
    $("flowScopeControl").querySelectorAll("button").forEach((item) => {
      const selected = item === button;
      item.classList.toggle("active", selected);
      item.setAttribute("aria-pressed", String(selected));
    });
    if (state.snapshot) {
      renderMap(state.snapshot);
      renderFlows(state.snapshot);
    }
  });
  $("flowKindControl").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-flow-kind]");
    if (!button) return;
    state.flowKind = button.dataset.flowKind;
    $("flowKindControl").querySelectorAll("button").forEach((item) => {
      const selected = item === button;
      item.classList.toggle("active", selected);
      item.setAttribute("aria-pressed", String(selected));
    });
    if (state.snapshot) renderFlows(state.snapshot);
  });
  // EdgeWatch clickable active streams
  const streamHero = $("streamHero");

  const streamTile =
    streamHero?.closest(
      ".activity-grid > div"
    ) ||
    streamHero?.parentElement;

  if (streamHero && streamTile) {
    const showActiveStreams = () => {
      if (state.snapshot) {
        openStreamClientsDrawer(state.snapshot);
      }
    };

    streamTile.classList.add(
      "activity-link"
    );

    streamTile.setAttribute(
      "role",
      "button"
    );

    streamTile.setAttribute(
      "tabindex",
      "0"
    );

    streamTile.setAttribute(
      "aria-label",
      "Show active Plex streams"
    );

    streamTile.setAttribute(
      "title",
      "Show active Plex streams"
    );

    streamTile.addEventListener(
      "click",
      showActiveStreams
    );

    streamTile.addEventListener(
      "keydown",
      (event) => {
        if (
          event.key === "Enter" ||
          event.key === " "
        ) {
          event.preventDefault();
          showActiveStreams();
        }
      }
    );
  }

  const remoteClientCard = $("remoteClientCard");
  remoteClientCard?.addEventListener("click", () => {
    if (state.snapshot) openRemoteClientsDrawer(state.snapshot);
  });

  const remoteStreamCard = $("remoteStreamCard");
  remoteStreamCard?.addEventListener("click", () => {
    if (state.snapshot) openStreamClientsDrawer(state.snapshot, { scope: "remote" });
  });

  // EdgeWatch clickable findings tile
  const findingHero = $("findingHero");
  const findingTile =
    findingHero?.parentElement;

  if (findingHero && findingTile) {
    const showFindings = () => {
      const panel =
        $("findingSummary")
          ?.closest(".panel");

      panel?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });

      panel?.classList.remove(
        "finding-target-highlight"
      );

      window.requestAnimationFrame(
        () => {
          panel?.classList.add(
            "finding-target-highlight"
          );

          window.setTimeout(
            () =>
              panel?.classList.remove(
                "finding-target-highlight"
              ),
            1400
          );
        }
      );

      const count = number(
        findingHero.textContent
      );

      showToast(
        count === 1
          ? "Showing 1 security finding"
          : `Showing ${count} security findings`
      );
    };

    findingTile.classList.add(
      "finding-link"
    );

    findingTile.setAttribute(
      "role",
      "button"
    );

    findingTile.setAttribute(
      "tabindex",
      "0"
    );

    findingTile.setAttribute(
      "aria-label",
      "Show security findings and actions"
    );

    findingTile.setAttribute(
      "title",
      "Show security findings and actions"
    );

    findingTile.addEventListener(
      "click",
      showFindings
    );

    findingTile.addEventListener(
      "keydown",
      (event) => {
        if (
          event.key === "Enter" ||
          event.key === " "
        ) {
          event.preventDefault();
          showFindings();
        }
      }
    );
  }

  const peerHero = $("peerHero");

  if (peerHero) {
    const showActivePublicPeers = () => {
      const publicButton = document.querySelector(
        '#flowKindControl [data-flow-kind="public"]'
      );
      const activeButton = document.querySelector(
        '#flowScopeControl [data-flow-scope="active"]'
      );

      publicButton?.click();
      activeButton?.click();

      window.requestAnimationFrame(() => {
        $("flowTitle")?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      });

      showToast("Showing active public peers");
    };

    peerHero.setAttribute("role", "button");
    peerHero.setAttribute("tabindex", "0");
    peerHero.setAttribute(
      "aria-label",
      "Show active public peers"
    );
    peerHero.setAttribute(
      "title",
      "Show active public peers"
    );

    peerHero.style.cursor = "pointer";
    peerHero.style.touchAction = "manipulation";
    peerHero.style.textDecoration = "underline dotted";
    peerHero.style.textUnderlineOffset = "4px";

    peerHero.addEventListener(
      "click",
      showActivePublicPeers
    );

    peerHero.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        showActivePublicPeers();
      }
    });
  }

  window.addEventListener("resize", () => {
    window.cancelAnimationFrame(state.chartFrame);
    state.chartFrame = window.requestAnimationFrame(drawChart);
  });
  refreshSnapshot();
  refreshHistory();
  connectLive();
  window.setInterval(refreshHistory, 15000);
  window.setInterval(() => {
    if (Date.now() - state.lastLiveAt > 15000) refreshSnapshot();
  }, 10000);
}


function connectionDetailStat(label, value) {
  const item = node("div", "metric-detail-stat");
  item.appendChild(node("span", "", label));
  item.appendChild(node("strong", "", String(value)));
  return item;
}

function connectionDetailRow(peer, internal = false) {
  const item = node("article", "metric-detail-row");
  const main = node("div", "metric-detail-main");

  const displayName =
    internal && peer.name && peer.name !== peer.ip
      ? peer.name
      : peer.ip || peer.name || "Unknown peer";

  main.appendChild(node("strong", "", displayName));

  const services = Array.isArray(peer.services)
    ? peer.services
        .map((service) => service.name)
        .filter(Boolean)
        .join(" · ")
    : "";

  const localPorts = Array.isArray(peer.local_ports)
    ? peer.local_ports.join(", ")
    : "";

  const parts = [];

  if (internal && peer.ip && displayName !== peer.ip) {
    parts.push(peer.ip);
  }

  if (!internal) {
    parts.push(locationLabel(peer));

    if (peer.organization) {
      parts.push(peer.organization);
    }
  }

  if (services) {
    parts.push(services);
  }

  if (localPorts) {
    parts.push(`Local ports ${localPorts}`);
  }

  main.appendChild(
    node(
      "small",
      "",
      parts.filter(Boolean).join(" · ") || "No additional details"
    )
  );

  item.appendChild(main);

  const count = node("div", "metric-detail-count");
  count.appendChild(
    node(
      "strong",
      "",
      String(number(peer.connections))
    )
  );
  count.appendChild(
    node(
      "span",
      "",
      peer.direction || (internal ? "internal" : "flow")
    )
  );

  item.appendChild(count);
  return item;
}

function closeConnectionMetricDrawer() {
  const drawer = $("metricDrawer");
  const backdrop = $("metricDrawerBackdrop");

  if (!drawer || !backdrop) return;

  drawer.classList.remove("open");
  backdrop.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
  document.body.classList.remove("metric-drawer-open");

  window.setTimeout(() => {
    drawer.hidden = true;
    backdrop.hidden = true;
  }, 220);
}

function openConnectionMetricDrawer(kind) {
  const drawer = $("metricDrawer");
  const backdrop = $("metricDrawerBackdrop");
  const title = $("metricDrawerTitle");
  const subtitle = $("metricDrawerSubtitle");
  const body = $("metricDrawerBody");

  if (!drawer || !backdrop || !title || !subtitle || !body) {
    return;
  }

  const snapshot = state.snapshot || {};
  const connections = snapshot.network?.connections || {};
  const publicPeers = Array.isArray(connections.public_peers)
    ? connections.public_peers
    : [];
  const internalPeers = Array.isArray(connections.internal_peers)
    ? connections.internal_peers
    : [];

  clear(body);

  if (kind === "tcp") {
    title.textContent = "Established TCP sockets";
    subtitle.textContent =
      "Current socket classification on the EdgeWatch VPS";

    const grid = node("div", "metric-detail-grid");

    for (const [label, value] of [
      ["Total", number(connections.established)],
      ["Public", number(connections.public_connection_count)],
      ["Internal", number(connections.internal_connection_count)],
      [
        "Loopback",
        number(
          connections.loopback_connection_count,
          number(connections.local_connection_count)
        ),
      ],
      ["Other", number(connections.other_connection_count)],
    ]) {
      grid.appendChild(connectionDetailStat(label, value));
    }

    body.appendChild(grid);
    body.appendChild(
      node(
        "div",
        "metric-detail-note",
        "The total includes established TCP sockets classified as public, private or WireGuard, loopback, and any connections that could not be cleanly classified."
      )
    );
  } else if (kind === "public") {
    title.textContent = "Public connections";
    subtitle.textContent =
      `${number(connections.public_connection_count)} active connections grouped by remote IP`;

    if (!publicPeers.length) {
      body.appendChild(
        node(
          "div",
          "metric-detail-note",
          "No public TCP peers are active in the current sample."
        )
      );
    }

    for (const peer of publicPeers) {
      body.appendChild(connectionDetailRow(peer));
    }
  } else if (kind === "unique") {
    title.textContent = "Unique public IPs";
    subtitle.textContent =
      `${number(
        connections.unique_public_peer_count,
        number(connections.public_peer_count)
      )} active remote addresses`;

    if (!publicPeers.length) {
      body.appendChild(
        node(
          "div",
          "metric-detail-note",
          "No unique public IPs are active in the current sample."
        )
      );
    }

    for (const peer of publicPeers) {
      body.appendChild(connectionDetailRow(peer));
    }
  } else if (kind === "internal") {
    title.textContent = "Internal connections";
    subtitle.textContent =
      `${number(connections.internal_connection_count)} private or WireGuard connections`;

    if (!internalPeers.length) {
      body.appendChild(
        node(
          "div",
          "metric-detail-note",
          "No internal peers are active in the current sample."
        )
      );
    }

    for (const peer of internalPeers) {
      body.appendChild(connectionDetailRow(peer, true));
    }
  } else if (kind === "loopback") {
    const loopbackCount = number(
      connections.loopback_connection_count,
      number(connections.local_connection_count)
    );

    title.textContent = "Loopback connections";
    subtitle.textContent =
      `${loopbackCount} established local connections`;

    const grid = node("div", "metric-detail-grid");
    grid.appendChild(
      connectionDetailStat(
        "Loopback sockets",
        loopbackCount
      )
    );
    body.appendChild(grid);

    body.appendChild(
      node(
        "div",
        "metric-detail-note",
        "Loopback connections stay entirely on the VPS, usually between local services using 127.0.0.1 or ::1. They are not Internet traffic and do not consume the Linode transfer quota."
      )
    );
  }

  drawer.hidden = false;
  backdrop.hidden = false;
  drawer.setAttribute("aria-hidden", "false");
  document.body.classList.add("metric-drawer-open");

  window.requestAnimationFrame(() => {
    backdrop.classList.add("open");
    drawer.classList.add("open");
  });
}

function bindConnectionMetricDrawers() {
  const bindings = {
    tcpSocketCount: "tcp",
    publicConnectionCount: "public",
    uniquePublicCount: "unique",
    internalConnectionCount: "internal",
    localConnectionCount: "loopback",
  };

  for (const [elementId, kind] of Object.entries(bindings)) {
    const value = $(elementId);
    const card = value?.closest("div");

    if (!card) continue;

    card.classList.add("metric-clickable");
    card.setAttribute("role", "button");
    card.setAttribute("tabindex", "0");
    card.setAttribute(
      "aria-label",
      `Open ${kind} connection details`
    );

    const activate = () =>
      openConnectionMetricDrawer(kind);

    card.addEventListener("click", activate);

    card.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        activate();
      }
    });
  }

  $("metricDrawerClose")?.addEventListener(
    "click",
    closeConnectionMetricDrawer
  );

  $("metricDrawerBackdrop")?.addEventListener(
    "click",
    closeConnectionMetricDrawer
  );

  document.addEventListener("keydown", (event) => {
    if (
      event.key === "Escape" &&
      !$("metricDrawer")?.hidden
    ) {
      closeConnectionMetricDrawer();
    }
  });
}

document.addEventListener("DOMContentLoaded", start);
document.addEventListener("DOMContentLoaded", bindPeerInsightDrawer);
document.addEventListener("DOMContentLoaded", bindConnectionMetricDrawers);


// EdgeWatch Entra account identity

const edgewatchIdentity = {
  loaded: false,
  error: "",
  email: "",
  name: "",
  user: "",
  groups: [],
  provider: "Microsoft Entra ID",
  directoryName: "",
  tenantId: "",
  applicationName: "EdgeWatch",
  clientId: "",
  accessLabel: "Assigned enterprise application user",
  sessionLifetime: "",
  sessionRefresh: "",
};

function edgewatchText(value) {
  return String(value ?? "").trim();
}

function edgewatchDisplayNameFromEmail(email) {
  const local = edgewatchText(email)
    .split("@")[0]
    .replace(/[._-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  if (!local) {
    return "Signed-in user";
  }

  return local
    .split(" ")
    .filter(Boolean)
    .map(
      (part) =>
        part.charAt(0).toUpperCase() +
        part.slice(1)
    )
    .join(" ");
}

function edgewatchIdentityName(info) {
  const explicit = edgewatchText(
    info?.name ||
    info?.display_name ||
    info?.displayName
  );

  if (explicit) {
    return explicit;
  }

  const user = edgewatchText(
    info?.user ||
    info?.preferred_username ||
    info?.preferredUsername
  );

  if (
    user &&
    !user.includes("@") &&
    user.includes(" ")
  ) {
    return user;
  }

  return edgewatchDisplayNameFromEmail(
    info?.email ||
    user
  );
}

function edgewatchIdentityEmail(info) {
  return edgewatchText(
    info?.email ||
    info?.preferred_username ||
    info?.preferredUsername ||
    info?.user
  );
}

function edgewatchIdentityInitials(name) {
  const words = edgewatchText(name)
    .split(/\s+/)
    .filter(Boolean);

  if (!words.length) {
    return "EW";
  }

  if (words.length === 1) {
    return words[0]
      .slice(0, 2)
      .toUpperCase();
  }

  return (
    words[0].charAt(0) +
    words[words.length - 1].charAt(0)
  ).toUpperCase();
}

function edgewatchIdentityGroups(info) {
  const values =
    Array.isArray(info?.groups)
      ? info.groups
      : [];

  return values
    .map(edgewatchText)
    .filter(Boolean);
}

function edgewatchLocalLogoutUrl() {
  const destination = `${window.location.origin}/signed-out`;

  return (
    "/oauth2/sign_out?rd=" +
    encodeURIComponent(destination)
  );
}

function edgewatchMicrosoftLogoutUrl() {
  const providerLogout =
    "https://login.microsoftonline.com/common/oauth2/v2.0/logout";

  return (
    "/oauth2/sign_out?rd=" +
    encodeURIComponent(providerLogout)
  );
}

function updateEdgewatchAccountButton() {
  const button =
    document.getElementById(
      "accountButton"
    );

  const name =
    document.getElementById(
      "accountName"
    );

  const email =
    document.getElementById(
      "accountEmail"
    );

  if (!button || !name || !email) {
    return;
  }

  if (edgewatchIdentity.error) {
    name.textContent = "Account";
    email.textContent =
      "Unable to load identity";

    button.title =
      "Signed-in account details unavailable";

    return;
  }

  if (!edgewatchIdentity.loaded) {
    name.textContent = "Signed in";
    email.textContent =
      "Microsoft Entra ID";

    button.title =
      "Signed in with Microsoft Entra ID";

    return;
  }

  const displayName =
    edgewatchIdentity.name ||
    "Signed-in user";

  const displayEmail =
    edgewatchIdentity.email ||
    "Microsoft Entra ID";

  name.textContent = displayName;
  email.textContent = displayEmail;

  button.title =
    `${displayName} · ${displayEmail}`;
}

async function loadEdgewatchIdentity() {
  try {
    const response = await fetch(
      "/oauth2/userinfo",
      {
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          Accept: "application/json",
        },
      }
    );

    if (!response.ok) {
      throw new Error(
        `Identity service returned HTTP ${
          response.status
        }`
      );
    }

    const info = await response.json();
    let metadata = {};

    try {
      const metadataResponse = await fetch(
        "/api/v1/identity",
        {
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            Accept: "application/json",
          },
        }
      );

      if (metadataResponse.ok) {
        metadata = await metadataResponse.json();
      } else {
        console.warn(
          "EdgeWatch identity metadata returned HTTP " +
          metadataResponse.status
        );
      }
    } catch (metadataError) {
      console.warn(
        "Could not load EdgeWatch identity metadata.",
        metadataError
      );
    }

    edgewatchIdentity.email =
      edgewatchIdentityEmail(info);

    edgewatchIdentity.name =
      edgewatchIdentityName(info);

    edgewatchIdentity.user =
      edgewatchText(
        info?.user ||
        info?.preferred_username ||
        info?.preferredUsername
      );

    edgewatchIdentity.groups =
      edgewatchIdentityGroups(info);

    edgewatchIdentity.provider =
      edgewatchText(metadata?.provider) ||
      "Microsoft Entra ID";

    edgewatchIdentity.directoryName =
      edgewatchText(metadata?.directory_name);

    edgewatchIdentity.tenantId =
      edgewatchText(metadata?.tenant_id);

    edgewatchIdentity.applicationName =
      edgewatchText(metadata?.application_name) ||
      "EdgeWatch";

    edgewatchIdentity.clientId =
      edgewatchText(metadata?.client_id);

    edgewatchIdentity.accessLabel =
      edgewatchText(metadata?.access_label) ||
      "Assigned enterprise application user";

    edgewatchIdentity.sessionLifetime =
      edgewatchText(metadata?.session_lifetime);

    edgewatchIdentity.sessionRefresh =
      edgewatchText(metadata?.session_refresh);

    edgewatchIdentity.loaded = true;
    edgewatchIdentity.error = "";
  } catch (error) {
    edgewatchIdentity.loaded = false;
    edgewatchIdentity.error =
      error instanceof Error
        ? error.message
        : String(error);
  }

  updateEdgewatchAccountButton();
}

function openEdgewatchIdentityDrawer() {
  const email =
    edgewatchIdentity.email ||
    "Unavailable";

  const name =
    edgewatchIdentity.name ||
    edgewatchDisplayNameFromEmail(
      email
    );

  showInsightDrawer({
    eyebrow: "SIGNED-IN ACCOUNT",
    title: name,
    subtitle: email,

    render(body) {
      const profile = node(
        "div",
        "identity-profile"
      );

      const avatar = node(
        "div",
        "identity-profile-avatar",
        edgewatchIdentityInitials(name)
      );

      const profileCopy = node(
        "div",
        "identity-profile-copy"
      );

      profileCopy.appendChild(
        node("strong", "", name)
      );

      profileCopy.appendChild(
        node("span", "", email)
      );

      profileCopy.appendChild(
        node(
          "small",
          "",
          `Authenticated by ${
            edgewatchIdentity.provider ||
            "Microsoft Entra ID"
          }`
        )
      );

      profile.appendChild(avatar);
      profile.appendChild(profileCopy);
      body.appendChild(profile);

      body.appendChild(
        insightSection("Identity details")
      );

      const details = node(
        "div",
        "insight-kv-grid"
      );

      const rows = [
        ["Display name", name],
        ["Email", email],
        [
          "Username",
          edgewatchIdentity.user,
        ],
        [
          "Identity provider",
          edgewatchIdentity.provider,
        ],
      ];

      if (edgewatchIdentity.directoryName) {
        rows.push([
          "Directory",
          edgewatchIdentity.directoryName,
        ]);
      }

      if (edgewatchIdentity.tenantId) {
        rows.push([
          "Tenant ID",
          edgewatchIdentity.tenantId,
        ]);
      }

      if (edgewatchIdentity.applicationName) {
        rows.push([
          "Application",
          edgewatchIdentity.applicationName,
        ]);
      }

      if (edgewatchIdentity.clientId) {
        rows.push([
          "Application (client) ID",
          edgewatchIdentity.clientId,
        ]);
      }

      if (edgewatchIdentity.accessLabel) {
        rows.push([
          "Access",
          edgewatchIdentity.accessLabel,
        ]);
      }

      if (edgewatchIdentity.sessionLifetime) {
        rows.push([
          "Session lifetime",
          edgewatchIdentity.sessionLifetime,
        ]);
      }

      if (edgewatchIdentity.sessionRefresh) {
        rows.push([
          "Session refresh",
          edgewatchIdentity.sessionRefresh,
        ]);
      }

      if (
        edgewatchIdentity.groups.length
      ) {
        rows.push([
          "Groups",
          edgewatchIdentity.groups.join(
            ", "
          ),
        ]);
      }

      for (const [label, value] of rows) {
        const row =
          insightRow(label, value);

        if (row) {
          details.appendChild(row);
        }
      }

      body.appendChild(details);

      body.appendChild(
        insightSection("Account actions")
      );

      const localSignout = node(
        "button",
        "identity-signout-button identity-signout-local",
        "Sign out of EdgeWatch"
      );

      localSignout.type = "button";

      localSignout.addEventListener(
        "click",
        () => {
          localSignout.disabled = true;
          localSignout.textContent =
            "Signing out…";

          window.location.assign(
            edgewatchLocalLogoutUrl()
          );
        }
      );

      const microsoftSignout = node(
        "button",
        "identity-signout-button identity-signout-microsoft",
        "Sign out of Microsoft completely"
      );

      microsoftSignout.type = "button";

      microsoftSignout.addEventListener(
        "click",
        () => {
          microsoftSignout.disabled = true;
          microsoftSignout.textContent =
            "Signing out everywhere…";

          window.location.assign(
            edgewatchMicrosoftLogoutUrl()
          );
        }
      );

      const actions = node(
        "div",
        "identity-signout-actions"
      );

      actions.appendChild(localSignout);
      actions.appendChild(
        microsoftSignout
      );

      body.appendChild(actions);

      body.appendChild(
        node(
          "div",
          "metric-detail-note identity-signout-note",
          (
            "EdgeWatch-only sign-out clears this " +
            "dashboard session while preserving " +
            "Microsoft single sign-on. Complete " +
            "sign-out also ends the Microsoft session."
          )
        )
      );
    },
  });
}

function initializeEdgewatchIdentity() {
  const button =
    document.getElementById(
      "accountButton"
    );

  if (!button) {
    return;
  }

  button.addEventListener(
    "click",
    openEdgewatchIdentityDrawer
  );

  updateEdgewatchAccountButton();
  loadEdgewatchIdentity();
}

if (document.readyState === "loading") {
  document.addEventListener(
    "DOMContentLoaded",
    initializeEdgewatchIdentity,
    { once: true }
  );
} else {
  initializeEdgewatchIdentity();
}


// EdgeWatch settings and active monitor users

const edgewatchUiDefaults = {
  showAccountLabel: false,
  compactDashboard: false,
  reduceMotion: false,
};

let edgewatchUiSettings = {
  ...edgewatchUiDefaults,
};

function loadEdgewatchUiSettings() {
  try {
    const stored =
      window.localStorage.getItem(
        "edgewatch.ui.settings.v1"
      );

    if (stored) {
      edgewatchUiSettings = {
        ...edgewatchUiDefaults,
        ...JSON.parse(stored),
      };
    }
  } catch (error) {
    console.warn(
      "Could not load EdgeWatch settings.",
      error
    );
  }
}

function saveEdgewatchUiSettings() {
  try {
    window.localStorage.setItem(
      "edgewatch.ui.settings.v1",
      JSON.stringify(
        edgewatchUiSettings
      )
    );
  } catch (error) {
    console.warn(
      "Could not save EdgeWatch settings.",
      error
    );
  }
}

function applyEdgewatchUiSettings() {
  document.body.classList.toggle(
    "edgewatch-show-account-label",
    Boolean(
      edgewatchUiSettings
        .showAccountLabel
    )
  );

  document.body.classList.toggle(
    "edgewatch-compact-dashboard",
    Boolean(
      edgewatchUiSettings
        .compactDashboard
    )
  );

  document.body.classList.toggle(
    "edgewatch-reduce-motion",
    Boolean(
      edgewatchUiSettings
        .reduceMotion
    )
  );
}

function edgewatchSettingRow(
  label,
  description,
  key
) {
  const row = node(
    "label",
    "edgewatch-setting-row"
  );

  const copy = node(
    "span",
    "edgewatch-setting-copy"
  );

  copy.appendChild(
    node("strong", "", label)
  );

  copy.appendChild(
    node("small", "", description)
  );

  const control = node(
    "span",
    "edgewatch-setting-control"
  );

  const input =
    document.createElement("input");

  input.type = "checkbox";

  input.checked = Boolean(
    edgewatchUiSettings[key]
  );

  input.setAttribute(
    "aria-label",
    label
  );

  const slider = node(
    "span",
    "edgewatch-setting-slider"
  );

  input.addEventListener(
    "change",
    () => {
      edgewatchUiSettings[key] =
        input.checked;

      saveEdgewatchUiSettings();
      applyEdgewatchUiSettings();
    }
  );

  control.appendChild(input);
  control.appendChild(slider);

  row.appendChild(copy);
  row.appendChild(control);

  return row;
}

function edgewatchMonitorTime(value) {
  if (!value) {
    return "Unknown";
  }

  const parsed = new Date(value);

  if (
    Number.isNaN(parsed.getTime())
  ) {
    return String(value);
  }

  return parsed.toLocaleTimeString(
    [],
    {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
    }
  );
}

function edgewatchLastActive(user) {
  const seconds = Number(
    user?.last_seen_seconds_ago || 0
  );

  if (seconds < 15) {
    return "Active now";
  }

  if (seconds < 60) {
    return `${Math.floor(seconds)} sec ago`;
  }

  return (
    `${Math.floor(seconds / 60)} min ago`
  );
}

function edgewatchActiveUserCard(user) {
  const current =
    edgewatchIdentity.email &&
    String(user?.email || "")
      .toLowerCase() ===
      edgewatchIdentity.email
        .toLowerCase();

  const card = node(
    "article",
    (
      "edgewatch-active-user" +
      (current
        ? " edgewatch-current-user"
        : "")
    )
  );

  const avatar = node(
    "div",
    "edgewatch-active-avatar",
    edgewatchIdentityInitials(
      user?.display_name ||
      user?.email ||
      "User"
    )
  );

  const copy = node(
    "div",
    "edgewatch-active-copy"
  );

  const heading = node(
    "div",
    "edgewatch-active-heading"
  );

  heading.appendChild(
    node(
      "strong",
      "",
      user?.display_name ||
      user?.email ||
      "Signed-in user"
    )
  );

  heading.appendChild(
    node(
      "span",
      "edgewatch-online-pill",
      current
        ? "You"
        : "Online"
    )
  );

  copy.appendChild(heading);

  copy.appendChild(
    node(
      "span",
      "",
      user?.email || "Email unavailable"
    )
  );

  copy.appendChild(
    node(
      "small",
      "",
      [
        user?.device,
        user?.browser,
        edgewatchLastActive(user),
      ]
        .filter(Boolean)
        .join(" · ")
    )
  );

  card.appendChild(avatar);
  card.appendChild(copy);

  return card;
}

async function edgewatchMonitorHeartbeat() {
  try {
    await fetch(
      "/api/v1/monitor-users/heartbeat",
      {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        keepalive: true,
        headers: {
          Accept: "application/json",
        },
      }
    );
  } catch (error) {
    console.debug(
      "Monitor-user heartbeat unavailable.",
      error
    );
  }
}

async function loadEdgewatchMonitorUsers(
  summary,
  list
) {
  summary.textContent =
    "Loading active sessions…";

  list.replaceChildren();

  try {
    const response = await fetch(
      "/api/v1/monitor-users",
      {
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          Accept: "application/json",
        },
      }
    );

    if (!response.ok) {
      throw new Error(
        `HTTP ${response.status}`
      );
    }

    const payload =
      await response.json();

    const users =
      Array.isArray(payload?.users)
        ? payload.users
        : [];

    summary.textContent = [
      `${Number(
        payload?.active_count || 0
      )} active session${
        Number(
          payload?.active_count || 0
        ) === 1
          ? ""
          : "s"
      }`,
      `${Number(
        payload?.user_count || 0
      )} user${
        Number(
          payload?.user_count || 0
        ) === 1
          ? ""
          : "s"
      }`,
      "seen within 5 minutes",
    ].join(" · ");

    if (!users.length) {
      list.appendChild(
        node(
          "div",
          "metric-detail-note",
          (
            "No active browser sessions are currently " +
            "reporting. Refresh this page once to " +
            "register the current session."
          )
        )
      );

      return;
    }

    users.forEach((user) => {
      list.appendChild(
        edgewatchActiveUserCard(user)
      );
    });
  } catch (error) {
    summary.textContent =
      "Active-user data unavailable";

    list.appendChild(
      node(
        "div",
        "metric-detail-note",
        (
          "EdgeWatch could not load the current " +
          "monitor-user roster."
        )
      )
    );
  }
}

function openEdgewatchSettingsDrawer() {
  showInsightDrawer({
    eyebrow: "EDGEWATCH SETTINGS",
    title: "Monitor preferences",
    subtitle:
      "Interface and active-user visibility",

    render(body) {
      body.appendChild(
        insightSection(
          "Active monitor users"
        )
      );

      const summary = node(
        "div",
        "edgewatch-active-summary",
        "Loading active sessions…"
      );

      const list = node(
        "div",
        "edgewatch-active-user-list"
      );

      body.appendChild(summary);
      body.appendChild(list);

      const refresh = node(
        "button",
        "edgewatch-users-refresh",
        "Refresh active users"
      );

      refresh.type = "button";

      refresh.addEventListener(
        "click",
        async () => {
          refresh.disabled = true;
          refresh.textContent =
            "Refreshing…";

          await edgewatchMonitorHeartbeat();

          await loadEdgewatchMonitorUsers(
            summary,
            list
          );

          refresh.disabled = false;
          refresh.textContent =
            "Refresh active users";
        }
      );

      body.appendChild(refresh);

      body.appendChild(
        node(
          "div",
          "metric-detail-note edgewatch-session-note",
          (
            "This is an activity roster, not a list of " +
            "every unexpired Microsoft or OAuth cookie. " +
            "A session disappears after its browser has " +
            "not contacted EdgeWatch for five minutes."
          )
        )
      );

      body.appendChild(
        insightSection(
          "Header"
        )
      );

      body.appendChild(
        edgewatchSettingRow(
          "Show account name",
          (
            "Display your name and email beside the " +
            "person icon."
          ),
          "showAccountLabel"
        )
      );

      body.appendChild(
        insightSection(
          "Display"
        )
      );

      body.appendChild(
        edgewatchSettingRow(
          "Compact dashboard",
          (
            "Reduce card spacing to show more " +
            "information at once."
          ),
          "compactDashboard"
        )
      );

      body.appendChild(
        edgewatchSettingRow(
          "Reduce motion",
          (
            "Disable most interface animations and " +
            "transitions."
          ),
          "reduceMotion"
        )
      );

      body.appendChild(
        insightSection(
          "Reset"
        )
      );

      const reset = node(
        "button",
        "edgewatch-settings-reset",
        "Restore default interface settings"
      );

      reset.type = "button";

      reset.addEventListener(
        "click",
        () => {
          edgewatchUiSettings = {
            ...edgewatchUiDefaults,
          };

          saveEdgewatchUiSettings();
          applyEdgewatchUiSettings();

          reset.textContent =
            "Defaults restored";

          window.setTimeout(
            () => {
              reset.textContent =
                "Restore default interface settings";
            },
            1500
          );
        }
      );

      body.appendChild(reset);

      edgewatchMonitorHeartbeat()
        .then(
          () =>
            loadEdgewatchMonitorUsers(
              summary,
              list
            )
        );
    },
  });
}

function initializeEdgewatchSettings() {
  const button =
    document.getElementById(
      "settingsButton"
    );

  loadEdgewatchUiSettings();
  applyEdgewatchUiSettings();

  if (button) {
    button.addEventListener(
      "click",
      openEdgewatchSettingsDrawer
    );
  }

  edgewatchMonitorHeartbeat();

  window.setInterval(
    edgewatchMonitorHeartbeat,
    30000
  );

  document.addEventListener(
    "visibilitychange",
    () => {
      if (
        document.visibilityState ===
        "visible"
      ) {
        edgewatchMonitorHeartbeat();
      }
    }
  );
}

if (document.readyState === "loading") {
  document.addEventListener(
    "DOMContentLoaded",
    initializeEdgewatchSettings,
    { once: true }
  );
} else {
  initializeEdgewatchSettings();
}

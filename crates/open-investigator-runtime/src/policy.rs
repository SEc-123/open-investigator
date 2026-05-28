use crate::model::InvestigationMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
}

impl PolicyDecision {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            reason: reason.into(),
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReadonlyPolicy {
    allow_shell: bool,
}

impl ReadonlyPolicy {
    pub fn new(mode: InvestigationMode) -> Self {
        Self {
            allow_shell: mode.allows_readonly_shell(),
        }
    }

    pub fn validate(&self, command: &str) -> PolicyDecision {
        let trimmed = command.trim();
        if trimmed.is_empty() {
            return PolicyDecision::deny("empty command");
        }
        if !self.allow_shell {
            return PolicyDecision::deny("readonly shell is disabled in safe mode; use -m inv");
        }
        validate_readonly_command(trimmed)
    }
}

pub fn validate_readonly_command(command: &str) -> PolicyDecision {
    let lower = command.to_ascii_lowercase();
    for needle in hard_deny_tokens() {
        if lower.contains(needle) {
            return PolicyDecision::deny(format!("blocked dangerous token `{needle}`"));
        }
    }

    if contains_write_redirection(&lower) {
        return PolicyDecision::deny("blocked output redirection/write operator");
    }

    for segment in lower.split(['|', ';', '&']) {
        let token = first_token(segment);
        if token.is_empty() {
            continue;
        }
        if !is_allowed_first_token(token) {
            return PolicyDecision::deny(format!("command `{token}` is not in readonly allowlist"));
        }
    }

    validate_command_specific_args(&lower)
}

fn contains_write_redirection(command: &str) -> bool {
    command.contains(">>")
        || command.contains(" 2>")
        || command.contains(" &>")
        || command.contains(" >")
        || command.contains("tee ")
}

fn first_token(segment: &str) -> &str {
    segment
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(['\'', '"'])
}

fn is_allowed_first_token(token: &str) -> bool {
    let token = token.trim_start_matches('/');
    let token = token.rsplit('/').next().unwrap_or(token);
    linux_allowed().contains(&token) || windows_allowed().contains(&token)
}

fn validate_command_specific_args(command: &str) -> PolicyDecision {
    if command.contains("find ") {
        for denied in [" -delete", " -exec", " -execdir", " -ok", " -fprint"] {
            if command.contains(denied) {
                return PolicyDecision::deny(format!(
                    "blocked unsafe find option `{}`",
                    denied.trim()
                ));
            }
        }
    }
    if command.contains("sed ") && command.contains(" -i") {
        return PolicyDecision::deny("blocked sed in-place edit");
    }
    if command.contains("systemctl ") {
        let allowed = [
            " status",
            " list-units",
            " list-unit-files",
            " list-timers",
            " cat",
            " show",
            " is-active",
            " is-enabled",
        ];
        if !allowed.iter().any(|item| command.contains(item)) {
            return PolicyDecision::deny("systemctl is limited to readonly subcommands");
        }
    }
    if command.contains("crontab ") && !command.contains(" -l") {
        return PolicyDecision::deny("crontab is limited to -l");
    }
    if command.starts_with("docker ") {
        let allowed = [
            " ps",
            " images",
            " inspect",
            " logs",
            " network ls",
            " volume ls",
            " info",
            " version",
        ];
        if !allowed.iter().any(|item| command.contains(item)) {
            return PolicyDecision::deny("docker is limited to readonly investigation subcommands");
        }
    }
    if command.starts_with("crictl ") {
        let allowed = [" ps", " images", " inspect", " logs", " info", " pods"];
        if !allowed.iter().any(|item| command.contains(item)) {
            return PolicyDecision::deny("crictl is limited to readonly investigation subcommands");
        }
    }
    if command.starts_with("ctr ") {
        let allowed = [
            " containers",
            " images",
            " tasks",
            " namespaces",
            " plugins",
        ];
        if !allowed.iter().any(|item| command.contains(item)) {
            return PolicyDecision::deny("ctr is limited to readonly investigation subcommands");
        }
    }
    if command.starts_with("kubectl ") {
        let allowed = [" get ", " describe ", " logs ", " top ", " version"];
        if !allowed.iter().any(|item| command.contains(item)) {
            return PolicyDecision::deny(
                "kubectl is limited to readonly investigation subcommands",
            );
        }
    }
    if command.starts_with("auditctl ") && !command.contains(" -s") {
        return PolicyDecision::deny("auditctl is limited to status checks");
    }
    if command.starts_with("dpkg ") {
        let allowed = [" -l", " --get-selections", " -s"];
        if !allowed.iter().any(|item| command.contains(item)) {
            return PolicyDecision::deny("dpkg is limited to readonly package queries");
        }
    }
    if command.starts_with("rpm ") {
        let allowed = [" -qa", " -qi", " -qf", " -V"];
        if !allowed.iter().any(|item| command.contains(item)) {
            return PolicyDecision::deny("rpm is limited to readonly package queries");
        }
    }
    PolicyDecision::allow("readonly command accepted by policy")
}

fn hard_deny_tokens() -> &'static [&'static str] {
    &[
        " rm ",
        "rm -",
        ";rm",
        " del ",
        "erase ",
        "remove-item",
        " rmdir ",
        " mv ",
        " move ",
        " cp ",
        " copy-item ",
        " chmod ",
        " chown ",
        " icacls ",
        " takeown ",
        " kill ",
        " pkill ",
        " taskkill ",
        " stop-process",
        "restart-service",
        " stop-service",
        "start-service",
        " set-service",
        "systemctl start",
        "systemctl stop",
        "systemctl restart",
        "systemctl enable",
        "systemctl disable",
        "service restart",
        "service stop",
        "service start",
        "iptables ",
        " ufw ",
        "firewall-cmd",
        "netsh ",
        "reg add",
        "reg delete",
        "set-item",
        "set-itemproperty",
        "new-item",
        "new-service",
        "new-scheduledtask",
        "remove-scheduledtask",
        "schtasks /create",
        "schtasks /delete",
        "schtasks /change",
        "net user",
        "net localgroup",
        "dsadd ",
        "dsmod ",
        "invoke-webrequest",
        "invoke-restmethod",
        "iwr ",
        "curl ",
        "wget ",
        "certutil -urlcache",
        "bitsadmin",
        "ftp ",
        "scp ",
        "sftp ",
        " nc ",
        "ncat ",
        "socat ",
        "bash -i",
        "sh -i",
        "python -c",
        "python3 -c",
        "perl -e",
        "ruby -e",
        "node -e",
        "php -r",
        "encodedcommand",
        "invoke-expression",
        "iex ",
        "$(",
        "`",
        "mkfs",
        "mount -o remount",
        "dd if=",
        "dd of=",
        "passwd ",
    ]
}

fn linux_allowed() -> &'static [&'static str] {
    &[
        "hostname",
        "uname",
        "date",
        "uptime",
        "whoami",
        "id",
        "ip",
        "ifconfig",
        "ps",
        "ss",
        "netstat",
        "lsof",
        "journalctl",
        "last",
        "lastlog",
        "who",
        "w",
        "getent",
        "cat",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "awk",
        "sed",
        "head",
        "tail",
        "stat",
        "find",
        "ls",
        "systemctl",
        "crontab",
        "df",
        "mount",
        "jcmd",
        "jps",
        "readlink",
        "basename",
        "dirname",
        "wc",
        "sort",
        "uniq",
        "lsmod",
        "auditctl",
        "ausearch",
        "lastb",
        "dpkg",
        "rpm",
        "docker",
        "crictl",
        "ctr",
        "kubectl",
    ]
}

fn windows_allowed() -> &'static [&'static str] {
    &[
        "get-process",
        "get-service",
        "get-nettcpconnection",
        "get-scheduledtask",
        "get-winevent",
        "get-eventlog",
        "get-localuser",
        "get-localgroupmember",
        "get-itemproperty",
        "get-childitem",
        "get-ciminstance",
        "get-computerinfo",
        "get-mpcomputerstatus",
        "get-timezone",
        "get-netipaddress",
        "select-object",
        "where-object",
        "format-table",
        "wevtutil",
        "tasklist",
        "netstat",
        "whoami",
        "hostname",
    ]
}

#[cfg(test)]
mod tests {
    use super::validate_readonly_command;

    #[test]
    fn denies_delete() {
        assert!(!validate_readonly_command("rm -rf /tmp/x").allowed);
    }

    #[test]
    fn allows_ps() {
        assert!(validate_readonly_command("ps auxww").allowed);
    }
}

package trivy

# Set which severities should cause a deny (fail the pipeline)
deny_severities = {"HIGH", "CRITICAL"}

# deny rule: emits a message object for each vulnerability that matches the deny set.
deny[msg] {
  some i
  result := input.Results[i]

  # skip results without Vulnerabilities
  vulns := result.Vulnerabilities
  vulns != null

  some j
  vuln := vulns[j]

  # normalize severity and check threshold
  severity := upper(vuln.Severity)
  severity_in_threshold(severity)

  msg := {
    "target": result.Target,
    "vulnerability": vuln.VulnerabilityID,
    "package": vuln.PkgName,
    "installed_version": vuln.InstalledVersion,
    "severity": severity,
    "title": vuln.Title
  }
}

# helper: check membership in deny set
severity_in_threshold(sev) {
  deny_severities[sev]
}

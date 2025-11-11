package trivy

# Configure which severities should cause a deny.
# Default: HIGH and CRITICAL
deny_severities = {"HIGH", "CRITICAL"}

# deny rule: one or more deny messages will be produced when a vulnerability
# has a severity in deny_severities.
deny[msg] {
  # iterate results array (trivy JSON -> .Results)
  some i
  result := input.Results[i]
  # results may not have Vulnerabilities key
  vulns := result.Vulnerabilities
  vulns != null
  some j
  vuln := vulns[j]

  # normalize severity (Trivy uses uppercase strings like "HIGH","CRITICAL")
  severity := upper(vuln.Severity)
  severity == s
  s == severity
  s == _

  # check threshold membership
  severity_in_threshold(severity)

  # build message for reporting
  target := result.Target
  id := vuln.VulnerabilityID
  pkg := vuln.PkgName
  version := vuln.InstalledVersion
  msg := sprintf("target=%v; vuln=%v; pkg=%v@%v; severity=%v", [target, id, pkg, version, severity])
}

# helper: check severity in deny set
severity_in_threshold(sev) {
  deny_severities[sev]
}

# Security policy

Kneepad reduces accidents. It is not a sandbox (see docs/THREAT_MODEL.md).

To report a way to bypass a rule, or a problem in the audit log, open a private security advisory on the repository
(Security tab, "Report a vulnerability") rather than a public issue. Bypasses of pattern rules are expected to exist and
are normal bugs: public issues with a failing example are welcome for those. Please use the private route for anything
that lets a hostile repository, config file or command run code, escape the audit log, or read secrets.

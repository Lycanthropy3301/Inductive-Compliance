Security depends on actual concrete state, not just intended state
- Configuration drift is when actua state diverges from the declared or intended state

Temporary changes
- enabling a debug port and forgetting to close it
- broadening IAM permissions temporarily
- installing unmaintained utility packages

Drift also harms forensics
- Drift is a slow process, it happens over time
- Logs sometimes have cutoffs (days, months, etc.)
- Mutated state can cause rollback failures

Relationship between state and security is also about preventing compromise

Configuration drift occurs when real systems diverge from approved baselines, that drift can introduce vulnerabilities, compliance failures, rollback problems, etc.

Two ways of mitigation
- minimizing state
- enforcing state

Fleet systems, cloud deployments are easy to change and often highly stateful

Deploying drift detection

**Prevention is better than the cure**

---

- Security depends on concrete states

---

Fleet systems and Cloud deployments are highly dynamic
- Easy to change by design
- Highly stateful
- Drift is much easier

---

Current drift handling:

Pipeline gates before deployment, 
Scheduled CI jobs or periodic plans
continuous GitOps reconcilliation loops
post-incident / on-demand checks

Current issues
1. Detection is delayed by design
    - Scheduled checks mean drift is discovered after system has diverged
    - Network overhead

3. Alert fatigue and false positives
    - Raw text diffing is noisy
    - Wrong drift detection methods can create as much noise as value
    - Operationally expensive

4. Human decision bottlenecks
    - Teams have to decide whether or not to restore the declared state
    - Or update the desired state to legitimize the change

5. Reconcilliation can be dangerous
    - Once drift exists, restoring truth is risky
    - "The next apply is a landmine"

7. Borad detection surface, complexity and cost
infrastructure,
Kubernetes,
containers,
applications,
databases,
secrets,
data contracts,
dashboards,
remediation loops,
scheduled jobs,
metrics, alerts, and runbooks.

Moving one step earlier

---

Current drift handling is... complicated
- Pipeline gates
- Schedule CI jobs
- Continuous GitOps reconcilliation
- Post incident checks

---

Detection is delayed by design.
- Most current solution check for drift *after* deployment.
- The system diverges *before* reconcilliation.
- There is a tradeoff between overhead and response time.

---

Detection is also usually noisy!
- A lot of sources detected drift through raw text diffing!
- Wrong drift detection methods can create as much noise as value.
- False positives can be operationally expensive and cause alert fatigue.

---

Speaking of alert fatigue...
- Human decision bottlenecks
- Theres always a decision between rollback and legitimization
- How often would these decisions be made?

---

Nix/NixOS expresses system configuration declaratively
- Services
- Firewall
- SSH settings
- packages
- system options

Configurations are explicit and defined
- outputs are addressable
- changes are structured
- generations and rollbacks are possible

Noninvasiveness
Not proving all of NixOS
- Handful of relevant options
- Projecting them into a simplified state model
- Reasoning over this state model

---

Deep inspection and telemetry are not a necesssary price for strong security
- The monitoring pipeline itself is a security system with its own attack surface
- Malware analysis and EDR platforms have been shown vulnerable to adverserial telemetry overload
- Observability guidice explicity warns that telemtry contains sensitive data, traffic patterns
- Invasive disclosure can backfire

Noninvasive security
- Principle of least privelege
- Verify only the minimum necessary information
- Excessive disclosure is both a privacy and security risk
- Strong verification can still be bound to a specific authorization context
- Suggests policy relevant state

---



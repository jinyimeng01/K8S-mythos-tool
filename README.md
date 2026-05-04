# K8S-mythos-tool

> Industrial Kubernetes red-team detection workbench for authorized assessment, cloud identity analysis, attack-path reasoning, and full-evidence reporting.

**Author:** T3Y

![Command Execution](img/Snipaste_2026-04-26_18-55-40.jpg)

---

## Overview

K8S-mythos-tool is a JavaFX-based Kubernetes security assessment workbench. It combines legacy red-team operator utilities with a modern **Advanced Detection** engine that performs read-only collection, risk attribution, cloud identity analysis, attack-path generation, and exportable evidence reports.

The project is organized as:

- `controller`: JavaFX event delegation and view orchestration.
- `core`: scan models, Kubernetes API access, detectors, attack-path generation, and report rendering.
- `helper`: table models, Pod/Secret parsing, and persistence helpers.
- `utils`: HTTP transport, JSON rendering, and kubectl integration.

## Core Capabilities

| Area | Capability |
|------|------------|
| Reconnaissance | Container/Kubernetes environment checks, capability decoding, Kubernetes port reference, ServiceAccount token guidance |
| Initial Access Validation | API Server exposure, Kubelet API checks, etcd exposure checks, Dashboard checks, kubeconfig parsing |
| Command Execution Utilities | API Server/Kubelet exec helpers, reverse shell payload generation, RBAC checks |
| Persistence Utilities | Admin ServiceAccount YAML, CronJob/DaemonSet persistence helpers, shadow kubeconfig generation |
| Privilege Escalation Utilities | Privileged container escape guidance, hostPath mount escape guidance, kernel escape references |
| Lateral Movement | Secret enumeration, Services/Endpoints/Nodes/NetworkPolicy review, taint-toleration Pod YAML generation |
| kubectl Panel | Common kubectl queries, custom command execution, backdoor Pod management helpers |
| Advanced Detection | Read-only scan engine, cloud identity deep inspection, attack-path reasoning, HTML/JSON/Markdown reports |

## Advanced Detection Workbench

Advanced Detection is the primary industrial detection workflow. It is designed to build a cluster profile, correlate identity and workload risks, and explain realistic attack paths without mutating the target cluster.

Panels include:

| Panel | Purpose |
|-------|---------|
| Cluster Profile | Kubernetes version, API discovery, node runtime, namespace and workload baseline, anonymous API discovery |
| Identity & RBAC | ClusterRoleBinding risks, current identity permission combinations, default ServiceAccount token signals |
| Workload Risk | privileged, hostPath, hostNetwork, hostPID/IPC, runtime socket mounts, CAP_SYS_ADMIN, broad tolerations |
| Network Exposure | NodePort/LoadBalancer services, public Endpoints, missing NetworkPolicy coverage |
| Cloud Identity | AWS, GCP, Azure, Alibaba Cloud, and generic workload identity indicators |
| Attack Paths | Identity -> Permission -> Resource -> Node/Cloud Context reasoning |
| Full Evidence Report | HTML, JSON, and Markdown reports with findings, evidence, standards, attack paths, and remediation guidance |

## Full Evidence Reporting

This build uses **Full Evidence Mode** by default.

Full Evidence reports intentionally preserve raw evidence values collected from Kubernetes API responses. Reports may include live tokens, Kubernetes Secrets, certificates, passwords, private keys, registry credentials, and cloud identity material.

Operator requirements:

- Use only on explicitly authorized engagements.
- Store reports in an approved encrypted location.
- Share reports only with approved stakeholders.
- Destroy reports according to the rules of engagement.
- Treat exported JSON, HTML, and Markdown files as sensitive evidence packages.

HTML reports escape evidence values before rendering. Full Evidence means values are preserved as text, not executed as markup.

## Cloud Identity Deep Inspection

K8S-mythos-tool inspects Kubernetes-native signals that often lead to cloud control-plane access:

- **AWS/EKS**: IRSA `eks.amazonaws.com/role-arn`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, AWS SDK environment variables, default ServiceAccount IAM role mapping.
- **GCP/GKE**: Workload Identity `iam.gke.io/gcp-service-account`, Google/GCP SDK environment variables, hostNetwork metadata reachability indicators.
- **Azure/AKS**: `azure.workload.identity/*` annotations and labels, `AZURE_*` and `MSI_*` environment variables, `api://AzureADTokenExchange` projected tokens.
- **Alibaba Cloud ACK**: RRSA `pod-identity.alibabacloud.com/*`, namespace injection, `ALIBABA_CLOUD_*`, `ALICLOUD_*`, `ALIYUN_*` environment variables, STS projected tokens.
- **Generic Cloud**: cross-provider workload identity annotations, hostNetwork metadata risk, and cloud credential environment variable patterns.

## Attack Path Engine

The attack-path engine converts findings into operator-readable chains:

- Anonymous API discovery -> cluster enumeration -> resource targeting.
- Sensitive RBAC combinations -> workload control -> Secret or node-facing access.
- privileged/hostPath/runtime socket -> node surface contact.
- Secret visibility -> credential reuse -> cross-component or external access.
- Workload identity annotations -> cloud role exchange -> external cloud API impact.
- hostNetwork -> metadata service -> node role exposure.
- cloud SDK environment variables -> external API access.

Each path includes prerequisite, evidence, reachable action, impact, remediation, and a lightweight graph view.

## UI/UX

The JavaFX interface uses a dedicated industrial console theme:

- Dark graphite and steel palette.
- Cyan and amber detection accents.
- High-contrast evidence consoles.
- Sharper table headers and panel boundaries.
- Dedicated Advanced Detection workbench layout.
- Full Evidence export warning in detection output and documentation.

The stylesheet lives at:

```text
src/main/resources/styles/mythos.css
```

## Architecture

```text
K8S-mythos-tool/
├── pom.xml
├── start.bat
├── src/main/java/
│   ├── module-info.java
│   └── com/k8spen/tool/
│       ├── Main.java
│       ├── Launcher.java
│       ├── controller/
│       ├── core/
│       │   ├── client/
│       │   ├── detector/
│       │   ├── engine/
│       │   ├── model/
│       │   └── report/
│       ├── helper/
│       └── utils/
├── src/main/resources/
│   ├── gui.fxml
│   ├── styles/mythos.css
│   └── kubectl.exe
├── src/test/java/
├── src/test/resources/fixtures/
└── img/
```

Java package names remain under `com.k8spen.tool` for compatibility with the current codebase.

## Build, Test, and Run

### Requirements

- JDK 17 or newer.
- Maven 3.6 or newer.
- Windows is recommended for `start.bat`; Java/Maven commands work cross-platform.

### Build

```bash
mvn package
```

The runnable fat jar is:

```text
target/k8s-mythos-tool-1.0.0.jar
```

### Test

```bash
mvn test
```

### Run on Windows

Double-click:

```bat
start.bat
```

Or run:

```bat
start.bat
```

### Run with Java

```bash
java -jar target/k8s-mythos-tool-1.0.0.jar
```

## Fixture Test Framework

The test suite includes reusable fixture helpers and Kubernetes response fixtures:

- `FixtureLoader`: loads fixture files from `src/test/resources/fixtures/`.
- `DetectorFixtureRunner`: creates scan snapshots and executes detectors against fixture maps.
- Fixtures cover RBAC, workloads, Secrets, network exposure, and cloud identity.

Current test coverage includes:

- RBAC permission evaluation.
- Workload risk detection.
- Secret full-evidence emission.
- Cloud identity detection.
- Attack-path generation.
- Report serialization and HTML escaping.
- Artifact naming and report branding.

## Safety and Authorization Notice

K8S-mythos-tool is for lawful, authorized security testing only. Some legacy panels can generate or execute high-impact Kubernetes actions such as command execution helpers, privileged workload YAML, persistence helpers, and credential review workflows.

You are responsible for:

- Obtaining written authorization.
- Staying within the approved scope.
- Understanding impact before using legacy high-risk panels.
- Protecting Full Evidence reports as sensitive material.
- Complying with applicable laws, contracts, and rules of engagement.

The authors and contributors are not responsible for misuse, unauthorized activity, or operational impact caused by this tool.

## License

MIT License. See [LICENSE](LICENSE).

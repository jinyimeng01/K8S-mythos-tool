# K8sPenTool

<p align="center">
  <strong>Industrial Kubernetes Red-Team Detection Workbench</strong><br>
  Authorized Assessment · Cloud Identity Analysis · Attack-Path Reasoning · Full-Evidence Reporting
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Java-17-blue?style=flat-square&logo=openjdk" alt="Java 17">
  <img src="https://img.shields.io/badge/JavaFX-17.0.2-blueviolet?style=flat-square&logo=java" alt="JavaFX">
  <img src="https://img.shields.io/badge/Maven-3.6+-orange?style=flat-square&logo=apachemaven" alt="Maven">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License">
</p>

---

## 📑 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Advanced Detection Workbench](#advanced-detection-workbench)
- [Cloud Identity Deep Inspection](#cloud-identity-deep-inspection)
- [Attack Path Engine](#attack-path-engine)
- [Full Evidence Reporting](#full-evidence-reporting)
- [UI/UX](#uiux)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Build](#build)
- [Test](#test)
- [Run](#run)
- [Fixture Test Framework](#fixture-test-framework)
- [Safety and Authorization Notice](#safety-and-authorization-notice)
- [License](#license)

---

## Overview

K8sPenTool is a JavaFX-based Kubernetes security assessment workbench designed for authorized red-team operators and security assessors. It combines traditional offensive utilities with a modern **Advanced Detection** engine that performs:

- **Read-only** cluster collection and profiling
- **Risk attribution** across workloads, RBAC, and network exposure
- **Cloud identity deep inspection** (AWS, GCP, Azure, Alibaba Cloud)
- **Attack-path generation** with prerequisite chains and remediation guidance
- **Exportable evidence reports** in HTML, JSON, and Markdown

The tool is built for **explicitly authorized engagements** where understanding Kubernetes attack surface, lateral movement paths, and cloud control-plane exposure is critical.

---

## Features

### Core Capability Matrix

| Area | Capability |
|------|------------|
| **Reconnaissance** | Container/Kubernetes environment detection, capability decoding, Kubernetes port reference, ServiceAccount token guidance |
| **Initial Access** | API Server exposure detection, Kubelet API checks, etcd exposure checks, Dashboard fingerprinting, kubeconfig parsing |
| **Command Execution** | API Server/Kubelet exec helpers, reverse shell payload generation, RBAC-aware execution |
| **Persistence** | Admin ServiceAccount YAML generation, CronJob/DaemonSet persistence helpers, shadow kubeconfig generation |
| **Privilege Escalation** | Privileged container escape guidance, hostPath mount escape, kernel escape references |
| **Lateral Movement** | Secret enumeration, Services/Endpoints/Nodes/NetworkPolicy review, taint-toleration Pod YAML generation |
| **kubectl Panel** | Common kubectl queries, custom command execution, backdoor Pod management helpers |
| **Advanced Detection** | Read-only scan engine, cloud identity inspection, attack-path reasoning, HTML/JSON/Markdown reports |

---

## Advanced Detection Workbench

The Advanced Detection module is the primary industrial-grade assessment workflow. It builds a comprehensive cluster profile, correlates identity and workload risks, and explains realistic attack paths **without mutating the target cluster**.

### Detection Panels

| Panel | Purpose |
|-------|---------|
| **Cluster Profile** | Kubernetes version, API discovery, node runtime, namespace baseline, workload inventory, anonymous API discovery |
| **Identity & RBAC** | ClusterRoleBinding risks, current identity permission combinations, default ServiceAccount token signals |
| **Workload Risk** | privileged containers, hostPath mounts, hostNetwork, hostPID/IPC, runtime socket mounts, CAP_SYS_ADMIN, broad tolerations |
| **Network Exposure** | NodePort/LoadBalancer services, public Endpoints, missing NetworkPolicy coverage |
| **Cloud Identity** | AWS IRSA, GCP Workload Identity, Azure Workload Identity, Alibaba Cloud RRSA, and generic identity indicators |
| **Attack Paths** | Identity → Permission → Resource → Node/Cloud context reasoning chains |
| **Full Evidence Report** | Consolidated HTML, JSON, and Markdown reports with findings, raw evidence, standards mapping, attack paths, and remediation |

---

## Cloud Identity Deep Inspection

K8sPenTool inspects Kubernetes-native signals that frequently lead to cloud control-plane access:

### AWS / EKS
- IRSA annotations: `eks.amazonaws.com/role-arn`
- Environment variables: `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`
- AWS SDK configuration signals
- Default ServiceAccount to IAM role mapping

### GCP / GKE
- Workload Identity annotations: `iam.gke.io/gcp-service-account`
- Google/GCP SDK environment variables
- hostNetwork metadata reachability indicators

### Azure / AKS
- Workload identity annotations and labels: `azure.workload.identity/*`
- Environment variables: `AZURE_*`, `MSI_*`
- Projected tokens with `api://AzureADTokenExchange`

### Alibaba Cloud / ACK
- RRSA annotations: `pod-identity.alibabacloud.com/*`
- Namespace injection patterns
- Environment variables: `ALIBABA_CLOUD_*`, `ALICLOUD_*`, `ALIYUN_*`
- STS projected tokens

### Generic Cloud
- Cross-provider workload identity annotations
- hostNetwork metadata service risk
- Cloud credential environment variable pattern matching

---

## Attack Path Engine

The attack-path engine converts discrete findings into operator-readable attack chains:

| Chain | Path |
|-------|------|
| **Anonymous Access** | Anonymous API discovery → cluster enumeration → resource targeting |
| **RBAC Abuse** | Sensitive RBAC combinations → workload control → Secret or node-facing access |
| **Container Escape** | privileged / hostPath / runtime socket → node surface contact |
| **Credential Reuse** | Secret visibility → credential reuse → cross-component or external access |
| **Cloud Pivot** | Workload identity annotations → cloud role exchange → external cloud API impact |
| **Metadata Exploitation** | hostNetwork → metadata service → node role exposure |
| **SDK Abuse** | Cloud SDK environment variables → external API access |

Each generated path includes:
- **Prerequisite**: Conditions required for the path to exist
- **Evidence**: Raw findings that support the path
- **Reachable Action**: What the operator can realistically do
- **Impact**: Scope of potential damage
- **Remediation**: Specific hardening recommendations
- **Graph View**: Lightweight node-edge visualization

---

## Full Evidence Reporting

This build operates in **Full Evidence Mode** by default.

Full Evidence reports intentionally preserve raw evidence values collected from Kubernetes API responses. These may include:

- Live ServiceAccount tokens
- Kubernetes Secrets and Secret data
- TLS certificates and private keys
- Registry credentials
- Cloud identity tokens and metadata

### Operator Requirements

- Use **only** on explicitly authorized engagements.
- Store reports in an **approved encrypted location**.
- Share reports **only** with approved stakeholders.
- Destroy reports according to the **rules of engagement**.
- Treat exported JSON, HTML, and Markdown files as **sensitive evidence packages**.

> **Note**: HTML reports escape evidence values before rendering. Full Evidence means values are preserved as text, not executed as markup.

---

## UI/UX

The JavaFX interface uses a dedicated industrial console theme optimized for long assessment sessions:

- **Dark graphite and steel** palette
- **Cyan and amber** detection accents for high-visibility findings
- **High-contrast** evidence consoles
- **Sharper table headers** and panel boundaries
- **Dedicated Advanced Detection** workbench layout
- **Full Evidence export warnings** embedded in detection output and documentation

The custom stylesheet is located at:
```text
src/main/resources/styles/mythos.css
```

---

## Architecture

```text
K8sPenTool/
├── pom.xml                              # Maven build configuration
├── start.bat                            # Windows launcher
├── .gitignore                           # Git ignore rules
├── .gitattributes                       # Git attributes (includes LFS rules)
│
├── src/main/java/
│   ├── module-info.java                 # Java module system declarations
│   └── com/k8spen/tool/
│       ├── Main.java                    # Application entry point
│       ├── Launcher.java                # JavaFX launcher wrapper
│       ├── controller/                  # JavaFX event delegation and view orchestration
│       │   ├── AccessHandler.java
│       │   ├── AdvancedDetectionHandler.java
│       │   ├── ControllerContext.java
│       │   ├── EscapeHandler.java
│       │   ├── ExecHandler.java
│       │   ├── InfoHandler.java
│       │   ├── KubectlHandler.java
│       │   ├── LateralHandler.java
│       │   ├── MainController.java
│       │   └── PersistHandler.java
│       ├── core/                        # Scan engine, detectors, models, reports
│       │   ├── client/                  # Kubernetes API client
│       │   ├── detector/                # Detection engines (RBAC, workload, cloud, network, secrets)
│       │   ├── engine/                  # Attack-path engine and scan orchestrator
│       │   ├── model/                   # Data models (Finding, Evidence, AttackPath, etc.)
│       │   └── report/                  # Report renderers (HTML, JSON, Markdown)
│       ├── helper/                      # Table models, Pod/Secret parsing, persistence helpers
│       └── utils/                       # HTTP transport, JSON rendering, kubectl integration
│
├── src/main/resources/
│   ├── gui.fxml                         # JavaFX UI layout
│   ├── styles/mythos.css                # Industrial console theme
│   └── kubectl.exe                      # Bundled kubectl binary (managed via Git LFS)
│
├── src/test/java/                       # Unit and fixture tests
├── src/test/resources/fixtures/         # Kubernetes API response fixtures for testing
└── img/                                 # Project image assets
```

Java package names remain under `com.k8spen.tool` for compatibility.

---

## Requirements

| Component | Minimum Version |
|-----------|-----------------|
| JDK | 17 |
| Maven | 3.6 |
| Operating System | Windows (recommended for `start.bat`); Java/Maven commands work cross-platform |

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/jinyimeng01/K8sPenTool.git
cd K8sPenTool
```

### 2. Verify Java Version

```bash
java -version
# Expected: openjdk 17 or newer
```

### 3. Verify Maven

```bash
mvn -version
# Expected: Apache Maven 3.6 or newer
```

---

## Build

Compile the project and package the runnable fat JAR:

```bash
mvn clean package
```

The shaded (fat) JAR containing all dependencies will be generated at:

```text
target/k8s-mythos-tool-1.0.0.jar
```

> The `original-k8s-mythos-tool-1.0.0.jar` in the same directory is the unshaded original and **cannot be run standalone**.

---

## Test

Run the full test suite:

```bash
mvn test
```

Current test coverage includes:

- RBAC permission evaluation
- Workload risk detection
- Secret full-evidence emission
- Cloud identity detection
- Attack-path generation
- Report serialization and HTML escaping
- Artifact naming and report branding

---

## Run

### Option 1: Windows Launcher

Double-click or execute:

```bat
start.bat
```

### Option 2: Direct Java Execution

```bash
java -jar target/k8s-mythos-tool-1.0.0.jar
```

### Option 3: Maven JavaFX Plugin

```bash
mvn javafx:run
```

---

## Fixture Test Framework

The test suite uses a reusable fixture framework for deterministic testing without a live cluster:

- **FixtureLoader**: Loads JSON fixture files from `src/test/resources/fixtures/`
- **DetectorFixtureRunner**: Creates scan snapshots and executes detectors against deserialized fixture maps
- **Coverage**: RBAC, workloads, Secrets, network exposure, and cloud identity fixtures

Example fixtures include:

```text
src/test/resources/fixtures/
├── cloud/
│   ├── aws-irsa-pod.json
│   ├── aws-irsa-serviceaccount.json
│   └── aws-node.json
├── network/
│   ├── empty-list.json
│   ├── endpoints-public-ip.json
│   └── nodeport-public-endpoint.json
├── rbac/
│   ├── clusterrolebindings-admin.json
│   ├── selfsubjectrules-admin.json
│   └── serviceaccounts-default.json
├── secrets/
│   └── service-account-token.json
└── workloads/
    └── privileged-hostpath-pod.json
```

---

## Safety and Authorization Notice

**K8sPenTool is for lawful, authorized security testing only.**

Some legacy panels can generate or execute high-impact Kubernetes actions, including:

- Command execution helpers
- Privileged workload YAML generation
- Persistence helpers (CronJob, DaemonSet, shadow kubeconfig)
- Credential review and extraction workflows

### Your Responsibilities

- Obtain **written authorization** before use.
- Stay within the **approved scope** at all times.
- **Understand impact** before using legacy high-risk panels.
- **Protect Full Evidence reports** as sensitive material.
- **Comply** with applicable laws, contracts, and rules of engagement.

### Disclaimer

The authors and contributors are **not responsible** for misuse, unauthorized activity, or operational impact caused by this tool.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for authorized Kubernetes security assessments.</sub>
</p>

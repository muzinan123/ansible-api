# ansible-api

A server automation wrapper built on the Ansible 1.x Python API — supporting dynamic Inventory generation, ad-hoc command execution, Playbook orchestration, and application deployment.

Designed for large-scale server fleet management in IDC environments, addressing operational challenges that manual processes cannot handle at scale.

---

## Background

This project was written during the **Python 2 / Ansible 1.x era** as a production-grade wrapper around the Ansible Python API.

At the time, Ansible had no stable high-level Python SDK. The recommended approach was to call internal modules like `ansible.runner` and `ansible.playbook` directly for programmatic control. This approach was deprecated in Ansible 2.x, which shifted toward `ansible-runner` and REST APIs (AWX/Tower).

Python 2 idioms in the code (`iteritems()`, `StandardError`) were standard practice at the time. **Migrating to Python 3 + Ansible 2.x API is the straightforward path for modern environments.**

---

## Architecture

```
MyInventory        →  Build server inventory programmatically (single host / grouped)
     ↓
MyRunner           →  Execute ad-hoc commands (shell / command / user modules)
     ↓
MyTask             →  High-level ops tasks (password rotation, server init, app deployment)
     ↓
MyPlaybook         →  Run Playbooks + parse structured results
     ↓
App                →  Application layer (dynamic Nginx config rendering & deployment)
```

---

## IDC Use Cases

**Bulk Server Initialization**
`MyInventory` pulls directly from a CMDB host list, and `MyTask` runs the full initialization pipeline — account setup, security baseline, NTP sync — across dozens to hundreds of machines in a single pass, ensuring environment consistency at scale.

**Large-Scale Credential Rotation**
`MyTask.chan_root_pw()` rotates system account passwords across a target host list in bulk. Passwords are SHA-512 hashed before being pushed via Ansible's `user` module. Results are returned per host — failed nodes feed directly into alerting or retry pipelines.

**Cluster Config Updates & Hot Deployment**
`App.nginx_conf_deploy()` accepts structured topology parameters, renders configs via Jinja2, and pushes them to all target nodes with a reload — solving the Nginx upstream sync problem during backend scale-out/in events and preventing config drift across nodes.

**Fleet-Wide Command Dispatch**
`MyRunner` matches target host groups by pattern and controls concurrency via `forks`, enabling second-level execution of health checks, disk cleanup, service restarts, or log collection across crawler nodes, storage nodes, or any defined host group.

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Programmatic Inventory** | Integrates directly with CMDB or dynamic host sources — no static hosts file to maintain at IDC scale |
| **Structured Result Parsing** | Separates `ok` / `failed` per host with meaningful output, ready for alerting systems or retry queues |
| **SHA-512 Password Hashing** | Pre-hashes credentials via `passlib` to keep plaintext out of task args and logs |
| **`become` / sudo Support** | Enforces least-privilege in IDC environments — ops accounts escalate on demand rather than running as root |
| **Playbook + Variable Injection** | Decouples config logic (Jinja2 templates) from deployment logic — one Playbook serves multiple host groups with different configs |

---

## Tech Stack

- Python 2.7
- Ansible 1.x
- `passlib` — password hashing (SHA-512)
- Jinja2 — config template rendering (via Ansible Playbook)


## 📝 Related Articles

📚 [Ansible Deep Dive: Architecture, Playbooks, API, Execution Internals & Performance Tuning](https://dev.to/jamesli/ansible-deep-dive-architecture-playbooks-api-execution-internals-performance-tuning-26bm)

📚 [Building an Ops Job Control System: Script Execution, File Distribution & Configuration Management](https://dev.to/jamesli/building-an-ops-job-control-system-script-execution-file-distribution-configuration-management-330h)


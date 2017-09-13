package main

const manifestTemplate = `
---
name: {{.DeploymentName}}

releases:
- name: {{.ReleaseName}}
  version: latest
- name: windows-utilities
  version: latest

stemcells:
- alias: windows
  os: {{.StemcellOS}}
  version: latest

update:
  canaries: 0
  canary_watch_time: 60000
  update_watch_time: 60000
  max_in_flight: 2

instance_groups:
- name: kms-host-enabled
  instances: 1
  stemcell: windows
  lifecycle: errand
  azs: [{{.AZ}}]
  vm_type: {{.VmType}}
  vm_extensions: [{{.VmExtensions}}]
  networks:
  - name: {{.Network}}
  jobs:
  - name: check_kms_host
    release: {{.ReleaseName}}
    properties:
      check_kms_host:
        host: test.test
        port: 1234
  - name: set_kms_host
    release: windows-utilities
    properties:
      set_kms_host:
        enabled: true
        host: test.test
        port: 1234
- name: kms-host-not-enabled
  instances: 1
  stemcell: windows
  lifecycle: errand
  azs: [{{.AZ}}]
  vm_type: {{.VmType}}
  vm_extensions: [{{.VmExtensions}}]
  networks:
  - name: {{.Network}}
  jobs:
  - name: check_kms_host
    release: {{.ReleaseName}}
    properties:
      check_kms_host:
        host:
        port:
  - name: set_kms_host
    release: windows-utilities
    properties:
      set_kms_host:
        enabled: false
        host: test.test
        port: 1234
- name: kms-host-enabled-with-default
  instances: 1
  stemcell: windows
  lifecycle: errand
  azs: [{{.AZ}}]
  vm_type: {{.VmType}}
  vm_extensions: [{{.VmExtensions}}]
  networks:
  - name: {{.Network}}
  jobs:
  - name: check_kms_host
    release: {{.ReleaseName}}
    properties:
      check_kms_host:
        host: test.test
        port: 1688
  - name: set_kms_host
    release: windows-utilities
    properties:
      set_kms_host:
        enabled: true
        host: test.test
        port:
`

const sshTemplate = `
---
name: {{.DeploymentName}}

releases:
- name: {{.ReleaseName}}
  version: latest
- name: windows-utilities
  version: latest

stemcells:
- alias: windows
  os: {{.StemcellOS}}
  version: latest

update:
  canaries: 0
  canary_watch_time: 60000
  update_watch_time: 60000
  max_in_flight: 2

instance_groups:
- name: check-ssh
  instances: 1
  stemcell: windows
  lifecycle: service # run as service
  azs: [{{.AZ}}]
  vm_type: {{.VmType}}
  vm_extensions: [{{.VmExtensions}}]
  networks:
  - name: {{.Network}}
  jobs:
  - name: enable_ssh
    release: windows-utilities
    properties:
      enable_ssh:
        enabled: {{.SSHEnabled}}
  - name: check_ssh
    release: {{.ReleaseName}}
    properties:
      check_ssh:
        expected: {{.SSHEnabled}}
`

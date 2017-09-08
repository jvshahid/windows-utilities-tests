# windows-utilities-tests

This repo houses tests used to verify Windows Utilities Release functions as expected.

# Example configuration

You can create a `config.json` file, eg:

```json
{
  "bosh": {
    "ca_cert": "<contents of your bosh director cert, with \n for newlines>",
    "client": "<bosh client name>",
    "client_secret": "<bosh client secret>",
    "target": "<IP of your bosh director>",
    "gw_private_key": "<contents of your bosh keypair private key, with \n for newlines>",
    "gw_user": "<bosh gw user e.g. vcap or jumpbox>"
  },
  "stemcell_path": "<absolute path to stemcell tgz>",
  "windows_utilities_path": "<absolute path to windows utilities release tgz>",
  "stemcell_os": "<os version, e.g. windows2012R2>",
  "az": "<area zone from bosh cloud config>",
  "vm_type": "<vm_type from bosh cloud config>",
  "vm_extensions": "<comma separated string of options, e.g. 50GB_ephemeral_disk>",
  "network": "<network from bosh cloud config>"
}
```

And then run these tests with `CONFIG_JSON=<path-to-config.json> ginkgo`.

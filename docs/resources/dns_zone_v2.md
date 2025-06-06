---
subcategory: "DNS / Designate"
layout: "openstack"
page_title: "OpenStack: openstack_dns_zone_v2"
sidebar_current: "docs-openstack-resource-dns-zone-v2"
description: |-
  Manages a DNS zone in the OpenStack DNS Service
---

# openstack\_dns\_zone\_v2

Manages a DNS zone in the OpenStack DNS Service.

## Example Usage

### Automatically detect the correct network

```hcl
resource "openstack_dns_zone_v2" "example_com" {
  name        = "example.com."
  email       = "jdoe@example.com"
  description = "An example zone"
  ttl         = 3000
  type        = "PRIMARY"
}
```

## Argument Reference

The following arguments are supported:

* `region` - (Optional) The region in which to obtain the V2 DNS client.
  If omitted, the `region` argument of the provider is used.
  Changing this creates a new DNS zone.

* `name` - (Required) The name of the zone. Note the `.` at the end of the name.
  Changing this creates a new DNS zone.

* `project_id` - (Optional) The ID of the project DNS zone is created
  for, sets `X-Auth-Sudo-Tenant-ID` header (requires an assigned 
  user role in target project).

* `email` - (Optional) The email contact for the zone record.

* `type` - (Optional) The type of zone. Can either be `PRIMARY` or `SECONDARY`.
  Changing this creates a new zone.

* `attributes` - (Optional) Attributes for the DNS Service scheduler.
  Changing this creates a new zone.

* `ttl` - (Optional) The time to live (TTL) of the zone.

* `description` - (Optional) A description of the zone.

* `masters` - (Optional) An array of master DNS servers. For when `type` is
  `SECONDARY`.

* `value_specs` - (Optional) Map of additional options. Changing this creates a
  new zone.

* `disable_status_check` - (Optional) Disable wait for zone to reach ACTIVE
  status. The check is enabled by default. If this argument is true, zone
  will be considered as created/updated if OpenStack request returned success.

## Attributes Reference

The following attributes are exported:

* `region` - See Argument Reference above.
* `name` - See Argument Reference above.
* `project_id` - See Argument Reference above.
* `email` - See Argument Reference above.
* `type` - See Argument Reference above.
* `attributes` - See Argument Reference above.
* `ttl` - See Argument Reference above.
* `description` - See Argument Reference above.
* `masters` - See Argument Reference above.
* `value_specs` - See Argument Reference above.

## Import

This resource can be imported by specifying the zone ID with optional project ID:

```
$ terraform import openstack_dns_zone_v2.zone_1 zone_id
$ terraform import openstack_dns_zone_v2.zone_1 zone_id/project_id
```

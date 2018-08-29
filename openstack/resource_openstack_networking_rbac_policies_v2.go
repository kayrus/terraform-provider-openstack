package openstack

import (
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/terraform/helper/schema"

	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/rbacpolicies"
)

const (
	ActionRegex = "(?:access_as_external|access_as_shared)"
)

func resourceNetworkingRBACPoliciesV2() *schema.Resource {
	return &schema.Resource{
		Create: resourceNetworkingRBACPoliciesV2Create,
		Read:   resourceNetworkingRBACPoliciesV2Read,
		Update: resourceNetworkingRBACPoliciesV2Update,
		Delete: resourceNetworkingRBACPoliciesV2Delete,

		Schema: map[string]*schema.Schema{
			"action": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validateAction(),
			},
			"object_type": {
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
			},
			"target_tenant": {
				Type:     schema.TypeString,
				Required: true,
			},
			"object_id": {
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
			},
		},
	}
}

func validateAction() schema.SchemaValidateFunc {
	return func(v interface{}, k string) (ws []string, errors []error) {
		value := v.(string)

		if !regexp.MustCompile(ActionRegex).MatchString(value) {
			errors = append(errors, fmt.Errorf(
				"%q name must be one of 'access_as_external' or 'access_as_shared'", value))
		}
		return
	}
}

func resourceNetworkingRBACPoliciesV2Create(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	networkingClient, err := config.networkingV2Client(GetRegion(d, config))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	createOpts := rbacpolicies.CreateOpts{
		Action:       rbacpolicies.PolicyAction(d.Get("action").(string)),
		ObjectType:   d.Get("object_type").(string),
		TargetTenant: d.Get("target_tenant").(string),
		ObjectID:     d.Get("object_id").(string),
	}

	log.Printf("[DEBUG] Create Options: %#v", createOpts)
	rbac, err := rbacpolicies.Create(networkingClient, createOpts).Extract()
	if err != nil {
		return fmt.Errorf("Error creating OpenStack Neutron RBAC policy: %s", err)
	}

	d.SetId(rbac.ID)

	return resourceNetworkingRBACPoliciesV2Read(d, meta)
}

func resourceNetworkingRBACPoliciesV2Read(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	networkingClient, err := config.networkingV2Client(GetRegion(d, config))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	rbac, err := rbacpolicies.Get(networkingClient, d.Id()).Extract()
	if err != nil {
		return CheckDeleted(d, err, "rbacpolicies")
	}

	log.Printf("[DEBUG] Retrieved RBAC policy %s: %+v", d.Id(), rbac)

	d.Set("action", string(rbac.Action))
	d.Set("object_type", rbac.ObjectType)
	d.Set("target_tenant", rbac.TargetTenant)
	d.Set("object_id", rbac.ObjectID)

	return nil
}

func resourceNetworkingRBACPoliciesV2Update(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	networkingClient, err := config.networkingV2Client(GetRegion(d, config))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	var hasChange bool
	var updateOpts rbacpolicies.UpdateOpts

	if d.HasChange("target_tenant") {
		hasChange = true
		updateOpts.TargetTenant = d.Get("target_tenant").(string)
	}

	if hasChange {
		_, err := rbacpolicies.Update(networkingClient, d.Id(), updateOpts).Extract()
		if err != nil {
			return fmt.Errorf("Error updating OpenStack RBAC policy: %s", err)
		}
	}

	return resourceNetworkingRBACPoliciesV2Read(d, meta)
}

func resourceNetworkingRBACPoliciesV2Delete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	networkingClient, err := config.networkingV2Client(GetRegion(d, config))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	err = rbacpolicies.Delete(networkingClient, d.Id()).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting OpenStack RBAC Policy: %s", err)
	}

	d.SetId("")
	return nil
}

package openstack

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"

	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/lbaas_v2/l7policies"
)

func resourceL7PolicyV2() *schema.Resource {
	return &schema.Resource{
		Create: resourceL7PolicyV2Create,
		Read:   resourceL7PolicyV2Read,
		Update: resourceL7PolicyV2Update,
		Delete: resourceL7PolicyV2Delete,
		Importer: &schema.ResourceImporter{
			resourceL7PolicyV2Import,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Update: schema.DefaultTimeout(10 * time.Minute),
			Delete: schema.DefaultTimeout(10 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"region": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ForceNew: true,
			},

			"tenant_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ForceNew: true,
			},

			"name": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			"description": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			"action": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					"REDIRECT_TO_POOL", "REDIRECT_TO_URL", "REJECT",
				}, true),
			},

			"listener_id": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"position": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			"redirect_pool_id": &schema.Schema{
				Type:          schema.TypeString,
				ConflictsWith: []string{"redirect_url"},
				Optional:      true,
			},

			"redirect_url": &schema.Schema{
				Type:          schema.TypeString,
				ConflictsWith: []string{"redirect_pool_id"},
				Optional:      true,
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(string)
					_, err := url.ParseRequestURI(value)
					if err != nil {
						errors = append(errors, fmt.Errorf("URL is not valid: %s", err))
					}
					return
				},
			},

			"admin_state_up": &schema.Schema{
				Type:     schema.TypeBool,
				Default:  true,
				Optional: true,
			},
		},
	}
}

func resourceL7PolicyV2Create(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	lbClient, err := chooseLBV2Client(d, config)
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	// Assign some required variables for use in creation.
	listenerID := d.Get("listener_id").(string)
	action := d.Get("action").(string)
	redirectPoolID := d.Get("redirect_pool_id").(string)
	redirectURL := d.Get("redirect_url").(string)

	// Ensure the right combination of options have been specified.
	err = checkL7policyAction(action, redirectURL, redirectPoolID)
	if err != nil {
		return fmt.Errorf("Unable to create l7policy: %s", err)
	}

	adminStateUp := d.Get("admin_state_up").(bool)
	createOpts := l7policies.CreateOpts{
		TenantID:       d.Get("tenant_id").(string),
		Name:           d.Get("name").(string),
		Description:    d.Get("description").(string),
		Action:         l7policies.Action(action),
		ListenerID:     listenerID,
		RedirectPoolID: redirectPoolID,
		RedirectURL:    redirectURL,
		AdminStateUp:   &adminStateUp,
	}

	if v, ok := d.GetOk("position"); ok {
		createOpts.Position = int32(v.(int))
	}

	log.Printf("[DEBUG] Create Options: %#v", createOpts)

	timeout := d.Timeout(schema.TimeoutCreate)

	// Make sure the associated pool is active before proceeding.
	if redirectPoolID != "" {
		err = waitForLBV2viaPool(lbClient, redirectPoolID, "ACTIVE", nil, timeout)
		if err != nil {
			return fmt.Errorf("Error getting %s pool status: %s", redirectPoolID, err)
		}
	}

	// Wait for Load Balancer via Listener to become active before continuing.
	err = waitForLBV2viaListener(lbClient, listenerID, "ACTIVE", lbPendingStatuses, timeout)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Create Options: %#v", createOpts)

	log.Printf("[DEBUG] Attempting to create l7policy")
	var l7policy *l7policies.L7Policy
	err = resource.Retry(timeout, func() *resource.RetryError {
		l7policy, err = l7policies.Create(lbClient, createOpts).Extract()
		if err != nil {
			return checkForRetryableError(err)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("Error creating l7policy: %s", err)
	}

	// Wait for Load Balancer via Listener to become active before continuing
	err = waitForLBV2viaListener(lbClient, listenerID, "ACTIVE", lbPendingStatuses, timeout)
	if err != nil {
		return err
	}

	d.SetId(l7policy.ID)

	return resourceL7PolicyV2Read(d, meta)
}

func resourceL7PolicyV2Read(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	lbClient, err := chooseLBV2Client(d, config)
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	l7policy, err := l7policies.Get(lbClient, d.Id()).Extract()
	if err != nil {
		return CheckDeleted(d, err, "l7policy")
	}

	log.Printf("[DEBUG] Retrieved l7policy %s: %#v", d.Id(), l7policy)

	d.Set("action", l7policy.Action)
	d.Set("description", l7policy.Description)
	d.Set("tenant_id", l7policy.TenantID)
	d.Set("name", l7policy.Name)
	d.Set("position", int(l7policy.Position))
	d.Set("redirect_url", l7policy.RedirectURL)
	d.Set("redirect_pool_id", l7policy.RedirectPoolID)
	d.Set("region", GetRegion(d, config))
	d.Set("admin_state_up", l7policy.AdminStateUp)

	return nil
}

func resourceL7PolicyV2Update(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	lbClient, err := chooseLBV2Client(d, config)
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	// Assign some required variables for use in updating.
	listenerID := d.Get("listener_id").(string)
	action := d.Get("action").(string)
	redirectPoolID := d.Get("redirect_pool_id").(string)
	redirectURL := d.Get("redirect_url").(string)

	var updateOpts l7policies.UpdateOpts

	if d.HasChange("action") {
		updateOpts.Action = l7policies.Action(action)
	}
	if d.HasChange("name") {
		name := d.Get("name").(string)
		updateOpts.Name = &name
	}
	if d.HasChange("description") {
		description := d.Get("description").(string)
		updateOpts.Description = &description
	}
	if d.HasChange("redirect_pool_id") {
		redirectPoolID = d.Get("redirect_pool_id").(string)

		updateOpts.RedirectPoolID = &redirectPoolID
	}
	if d.HasChange("redirect_url") {
		redirectURL = d.Get("redirect_url").(string)
		updateOpts.RedirectURL = &redirectURL
	}
	if d.HasChange("position") {
		updateOpts.Position = d.Get("position").(int32)
	}
	if d.HasChange("admin_state_up") {
		adminStateUp := d.Get("admin_state_up").(bool)
		updateOpts.AdminStateUp = &adminStateUp
	}

	// Ensure the right combination of options have been specified.
	err = checkL7policyAction(action, redirectURL, redirectPoolID)
	if err != nil {
		return err
	}

	// Make sure the pool is active before continuing.
	timeout := d.Timeout(schema.TimeoutUpdate)
	if redirectPoolID != "" {
		err = waitForLBV2viaPool(lbClient, redirectPoolID, "ACTIVE", nil, timeout)
		if err != nil {
			return fmt.Errorf("Error getting %s pool status: %s", redirectPoolID, err)
		}
	}

	// Wait for Load Balancer via Listener to become active before continuing
	err = waitForLBV2viaListener(lbClient, listenerID, "ACTIVE", lbPendingStatuses, timeout)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Updating l7policy %s with options: %#v", d.Id(), updateOpts)
	err = resource.Retry(timeout, func() *resource.RetryError {
		_, err = l7policies.Update(lbClient, d.Id(), updateOpts).Extract()
		if err != nil {
			return checkForRetryableError(err)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("Unable to update l7policy %s: %s", d.Id(), err)
	}

	// Wait for Load Balancer via Listener to become active before continuing
	err = waitForLBV2viaListener(lbClient, listenerID, "ACTIVE", lbPendingStatuses, timeout)
	if err != nil {
		return err
	}

	return resourceL7PolicyV2Read(d, meta)
}

func resourceL7PolicyV2Delete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	lbClient, err := chooseLBV2Client(d, config)
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	timeout := d.Timeout(schema.TimeoutDelete)
	listenerID := d.Get("listener_id").(string)
	// Wait for Load Balancer via Listener to become active before continuing
	err = waitForLBV2viaListener(lbClient, listenerID, "ACTIVE", lbPendingStatuses, timeout)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Attempting to delete l7policy %s", d.Id())
	err = resource.Retry(timeout, func() *resource.RetryError {
		err = l7policies.Delete(lbClient, d.Id()).ExtractErr()
		if err != nil {
			return checkForRetryableError(err)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("Error deleting l7policy %s: %s", d.Id(), err)
	}

	err = waitForLBV2L7Policy(lbClient, d.Id(), "DELETED", nil, timeout)
	if err != nil {
		return err
	}

	// Wait for Load Balancer via Listener to become active before continuing
	err = waitForLBV2viaListener(lbClient, listenerID, "ACTIVE", lbPendingStatuses, timeout)
	if err != nil {
		return err
	}

	return nil
}

func resourceL7PolicyV2Import(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	parts := strings.SplitN(d.Id(), "/", 2)
	if len(parts) != 2 {
		err := fmt.Errorf("Invalid format specified for l7 Policy. Format must be <listener id>/<l7policy id>")
		return nil, err
	}

	listenerID := parts[0]
	l7policyID := parts[1]

	d.SetId(l7policyID)
	d.Set("listener_id", listenerID)

	return []*schema.ResourceData{d}, nil
}

func checkL7policyAction(action, redirectURL, redirectPoolID string) error {
	if action == "REJECT" {
		if redirectURL != "" || redirectPoolID != "" {
			return fmt.Errorf(
				"redirect_url and redirect_pool_id must be empty when action is set to %s", action)
		}
	}

	if action == "REDIRECT_TO_POOL" && redirectURL != "" {
		return fmt.Errorf("redirect_url must be empty when action is set to %s", action)
	}

	if action == "REDIRECT_TO_URL" && redirectPoolID != "" {
		return fmt.Errorf("redirect_pool_id must be empty when action is set to %s", action)
	}

	return nil
}

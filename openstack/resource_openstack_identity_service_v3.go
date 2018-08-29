package openstack

import (
	"fmt"
	"log"

	"github.com/gophercloud/gophercloud/openstack/identity/v3/services"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceIdentityServiceV3() *schema.Resource {
	return &schema.Resource{
		Create: resourceIdentityServiceV3Create,
		Read:   resourceIdentityServiceV3Read,
		Update: resourceIdentityServiceV3Update,
		Delete: resourceIdentityServiceV3Delete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"type": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
		},
	}
}

func resourceIdentityServiceV3Create(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	identityClient, err := config.identityV3Client(GetRegion(d, config))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack identity client: %s", err)
	}

	enabled := d.Get("enabled").(bool)
	createOpts := services.CreateOpts{
		Extra: map[string]interface{}{
			"name":        d.Get("name").(string),
			"description": d.Get("description").(string),
		},
		Type:    d.Get("type").(string),
		Enabled: &enabled,
	}

	log.Printf("[DEBUG] Create Options: %#v", createOpts)
	service, err := services.Create(identityClient, createOpts).Extract()
	if err != nil {
		return fmt.Errorf("Error creating OpenStack service: %s", err)
	}

	d.SetId(service.ID)

	return resourceIdentityServiceV3Read(d, meta)
}

func resourceIdentityServiceV3Read(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	identityClient, err := config.identityV3Client(GetRegion(d, config))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack identity client: %s", err)
	}

	service, err := services.Get(identityClient, d.Id()).Extract()
	if err != nil {
		return CheckDeleted(d, err, "service")
	}

	log.Printf("[DEBUG] Retrieved OpenStack service: %#v", service)

	d.Set("name", service.Extra["name"])
	d.Set("description", service.Extra["description"])
	d.Set("type", service.Type)
	d.Set("enabled", service.Enabled)

	return nil
}

func resourceIdentityServiceV3Update(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	identityClient, err := config.identityV3Client(GetRegion(d, config))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack identity client: %s", err)
	}

	var hasChange bool
	var updateOpts services.UpdateOpts

	if d.HasChange("enabled") {
		hasChange = true
		enabled := d.Get("enabled").(bool)
		updateOpts.Enabled = &enabled
	}

	if d.HasChange("type") {
		hasChange = true
		updateOpts.Type = d.Get("type").(string)
	}

	if d.HasChange("name") || d.HasChange("description") {
		hasChange = true
		updateOpts.Extra = map[string]interface{}{
			"name":        d.Get("name").(string),
			"description": d.Get("description").(string),
		}
	}

	if hasChange {
		_, err := services.Update(identityClient, d.Id(), updateOpts).Extract()
		if err != nil {
			return fmt.Errorf("Error updating OpenStack services: %s", err)
		}
	}

	return resourceIdentityServiceV3Read(d, meta)
}

func resourceIdentityServiceV3Delete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	identityClient, err := config.identityV3Client(GetRegion(d, config))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack identity client: %s", err)
	}

	err = services.Delete(identityClient, d.Id()).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting OpenStack service: %s", err)
	}

	return nil
}

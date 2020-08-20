package openstack

import (
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"

	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/l7policies"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/pools"
)

func resourceOctaviaV2() *schema.Resource {
	poolSchema := &schema.Resource{
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"protocol": {
				Type:     schema.TypeString,
				Required: true,
				//ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					"TCP", "UDP", "HTTP", "HTTPS", "PROXY",
				}, false),
			},

			"lb_method": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					"ROUND_ROBIN", "LEAST_CONNECTIONS", "SOURCE_IP", "SOURCE_IP_PORT",
				}, false),
			},

			// TODO: update pool on persistence change
			"persistence": {
				Type:     schema.TypeList,
				Optional: true,
				//ForceNew: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:     schema.TypeString,
							Required: true,
							//ForceNew: true,
							ValidateFunc: validation.StringInSlice([]string{
								"SOURCE_IP", "HTTP_COOKIE", "APP_COOKIE",
							}, false),
						},

						"cookie_name": {
							Type:     schema.TypeString,
							Optional: true,
							//ForceNew: true,
						},
					},
				},
			},

			"admin_state_up": {
				Type:     schema.TypeBool,
				Default:  true,
				Optional: true,
			},

			"member": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},

						"address": {
							Type:     schema.TypeString,
							Required: true,
						},

						"protocol_port": {
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validation.IntBetween(1, 65535),
						},

						"weight": {
							Type:         schema.TypeInt,
							Optional:     true,
							Default:      1,
							ValidateFunc: validation.IntBetween(0, 256),
						},

						"subnet_id": {
							Type:     schema.TypeString,
							Optional: true,
						},

						"admin_state_up": {
							Type:     schema.TypeBool,
							Default:  true,
							Optional: true,
						},
					},
				},
			},

			"monitor": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},

						"type": {
							Type:     schema.TypeString,
							Required: true,
							//ForceNew: true,
							ValidateFunc: validation.StringInSlice([]string{
								"TCP", "UDP-CONNECT", "HTTP", "HTTPS", "TLS-HELLO", "PING",
							}, false),
						},

						"delay": {
							Type:     schema.TypeInt,
							Required: true,
						},

						"timeout": {
							Type:     schema.TypeInt,
							Required: true,
						},

						"max_retries": {
							Type:     schema.TypeInt,
							Required: true,
						},

						"max_retries_down": {
							Type:     schema.TypeInt,
							Optional: true,
							// default is 3
							// https://docs.openstack.org/api-ref/load-balancer/v2/?expanded=create-health-monitor-detail#create-health-monitor
							Default: 3,
						},

						"url_path": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},

						"http_method": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},

						"expected_codes": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},

						"admin_state_up": {
							Type:     schema.TypeBool,
							Default:  true,
							Optional: true,
						},
					},
				},
			},
		},
	}

	l7RuleSchema := &schema.Resource{
		Schema: map[string]*schema.Schema{
			"type": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					"COOKIE", "FILE_TYPE", "HEADER", "HOST_NAME", "PATH",
				}, true),
			},

			"compare_type": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					"CONTAINS", "STARTS_WITH", "ENDS_WITH", "EQUAL_TO", "REGEX",
				}, true),
			},

			"value": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					if len(v.(string)) == 0 {
						errors = append(errors, fmt.Errorf("'value' field should not be empty"))
					}
					return
				},
			},

			"key": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"invert": {
				Type:     schema.TypeBool,
				Default:  false,
				Optional: true,
			},

			"admin_state_up": {
				Type:     schema.TypeBool,
				Default:  true,
				Optional: true,
			},
		},
	}

	l7PolicySchema := &schema.Resource{
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"action": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					"REDIRECT_TO_POOL", "REDIRECT_TO_URL", "REJECT",
				}, true),
			},

			"position": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			"redirect_pool_id": {
				Type: schema.TypeString,
				//ConflictsWith: []string{"redirect_url"}, TODO
				Optional: true,
			},

			"redirect_url": {
				Type: schema.TypeString,
				//ConflictsWith: []string{"redirect_pool_id"}, TODO
				Optional: true,
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(string)
					_, err := url.ParseRequestURI(value)
					if err != nil {
						errors = append(errors, fmt.Errorf("URL is not valid: %s", err))
					}
					return
				},
			},

			"admin_state_up": {
				Type:     schema.TypeBool,
				Default:  true,
				Optional: true,
			},

			"l7rule": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     l7RuleSchema,
			},
		},
	}

	listenerSchema := &schema.Resource{
		Schema: map[string]*schema.Schema{
			"protocol": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					"TCP", "UDP", "HTTP", "HTTPS", "TERMINATED_HTTPS",
				}, false),
			},

			"protocol_port": {
				Type:     schema.TypeInt,
				Required: true,
				ForceNew: true,
			},

			"name": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			// TODO: verify whether we need this
			"default_pool_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"default_pool": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem:     poolSchema,
			},

			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"connection_limit": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			"default_tls_container_ref": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"sni_container_refs": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			"admin_state_up": {
				Type:     schema.TypeBool,
				Default:  true,
				Optional: true,
			},

			"timeout_client_data": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			"timeout_member_connect": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			"timeout_member_data": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			"timeout_tcp_inspect": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			"insert_headers": {
				Type:     schema.TypeMap,
				Optional: true,
				ForceNew: false,
			},

			"allowed_cidrs": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			"l7policy": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     l7PolicySchema,
			},
		},
	}

	return &schema.Resource{
		Create: resourceOctaviaV2Create,
		Read:   resourceOctaviaV2Read,
		Update: resourceOctaviaV2Update,
		Delete: resourceOctaviaV2Delete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Update: schema.DefaultTimeout(10 * time.Minute),
			Delete: schema.DefaultTimeout(5 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"region": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ForceNew: true,
			},

			"name": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"vip_network_id": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Computed: true,
			},

			"vip_subnet_id": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Computed: true,
			},

			"tenant_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ForceNew: true,
			},

			"vip_address": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ForceNew: true,
			},

			"vip_port_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"admin_state_up": {
				Type:     schema.TypeBool,
				Default:  true,
				Optional: true,
			},

			"flavor_id": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"loadbalancer_provider": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ForceNew: true,
			},

			"security_group_ids": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
			},

			"listener": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     listenerSchema,
			},

			"pool": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     poolSchema,
			},

			"tags": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			"all_tags": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceOctaviaV2Create(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	lbClient, err := chooseLBV2Client(d, config)
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	var (
		lbID      string
		vipPortID string
	)

	// Choose either the Octavia or Neutron create options.
	createOpts, err := octaviaLBCreateOptsV2(d, config)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG][Neutron] openstack_lb_loadbalancer_v2 create options: %#v", createOpts)
	lb, err := loadbalancers.Create(lbClient, createOpts).Extract()
	if err != nil {
		return fmt.Errorf("Error creating openstack_lb_loadbalancer_v2: %s", err)
	}
	lbID = lb.ID
	vipPortID = lb.VipPortID

	// Wait for load-balancer to become active before continuing.
	timeout := d.Timeout(schema.TimeoutCreate)
	err = waitForLBV2LoadBalancer(lbClient, lbID, "ACTIVE", lbPendingStatuses, timeout)
	if err != nil {
		return err
	}

	// Once the load-balancer has been created, apply any requested security groups
	// to the port that was created behind the scenes.
	networkingClient, err := config.NetworkingV2Client(GetRegion(d, config))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}
	if err := resourceLoadBalancerV2SetSecurityGroups(networkingClient, vipPortID, d); err != nil {
		return fmt.Errorf("Error setting openstack_lb_loadbalancer_v2 security groups: %s", err)
	}

	d.SetId(lbID)

	return resourceOctaviaV2Read(d, meta)
}

func resourceOctaviaV2Read(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	lbClient, err := chooseLBV2Client(d, config)
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	var vipPortID string

	lb, err := loadbalancers.Get(lbClient, d.Id()).Extract()
	if err != nil {
		return CheckDeleted(d, err, "Unable to retrieve openstack_lb_loadbalancer_v2")
	}

	log.Printf("[DEBUG][Octavia] Retrieved openstack_lb_loadbalancer_v2 %s: %#v", d.Id(), lb)

	d.Set("name", lb.Name)
	d.Set("description", lb.Description)
	d.Set("vip_subnet_id", lb.VipSubnetID)
	d.Set("vip_network_id", lb.VipNetworkID)
	d.Set("tenant_id", lb.ProjectID)
	d.Set("vip_address", lb.VipAddress)
	d.Set("vip_port_id", lb.VipPortID)
	d.Set("admin_state_up", lb.AdminStateUp)
	d.Set("flavor_id", lb.FlavorID)
	d.Set("loadbalancer_provider", lb.Provider)
	d.Set("region", GetRegion(d, config))

	var lstnrs []map[string]interface{}
	for _, v := range lb.Listeners {
		// TODO: detect when listeners contain the full tree
		if v.ID != "" {
			// listener element contains only ID, fetching the listener details
			l, err := listeners.Get(lbClient, v.ID).Extract()
			if err != nil {
				return err
			}
			if l.DefaultPoolID != "" {
				p, err := pools.Get(lbClient, l.DefaultPoolID).Extract()
				if err != nil {
					return err
				}
				l.DefaultPool = p
			}
			for i, v := range l.L7Policies {
				p, err := l7policies.Get(lbClient, v.ID).Extract()
				if err != nil {
					return err
				}
				polID := v.ID
				for i, v := range p.Rules {
					r, err := l7policies.GetRule(lbClient, polID, v.ID).Extract()
					if err != nil {
						return err
					}
					p.Rules[i] = *r
				}
				l.L7Policies[i] = *p
			}
			lstnrs = append(lstnrs, flattenOctaviaListenerV2(*l)...)
		}
	}
	d.Set("listener", lstnrs)

	var pls []map[string]interface{}
	for _, v := range lb.Pools {
		// TODO: detect when pool contains the full tree
		if v.ID != "" {
			p, err := pools.Get(lbClient, v.ID).Extract()
			if err != nil {
				return err
			}

			if len(p.Members) > 0 {
				// TODO: detect, when pool contains all member details
				v, err := pools.ListMembers(lbClient, v.ID, nil).AllPages()
				if err != nil {
					return err
				}
				m, err := pools.ExtractMembers(v)
				if err != nil {
					return err
				}
				p.Members = m
			}

			if p.MonitorID != "" {
				m, err := monitors.Get(lbClient, p.MonitorID).Extract()
				if err != nil {
					return err
				}
				p.Monitor = *m
			}

			pls = append(pls, flattenOctaviaPoolV2(*p)...)
		}
	}
	d.Set("pool", pls)

	vipPortID = lb.VipPortID

	// Get any security groups on the VIP Port.
	if vipPortID != "" {
		networkingClient, err := config.NetworkingV2Client(GetRegion(d, config))
		if err != nil {
			return fmt.Errorf("Error creating OpenStack networking client: %s", err)
		}
		if err := resourceLoadBalancerV2GetSecurityGroups(networkingClient, vipPortID, d); err != nil {
			return fmt.Errorf("Error getting port security groups for openstack_lb_loadbalancer_v2: %s", err)
		}
	}

	return nil
}

func resourceOctaviaV2Update(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	lbClient, err := chooseLBV2Client(d, config)
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	var updateOpts loadbalancers.UpdateOpts
	if d.HasChange("name") {
		name := d.Get("name").(string)
		updateOpts.Name = &name
	}
	if d.HasChange("description") {
		description := d.Get("description").(string)
		updateOpts.Description = &description
	}
	if d.HasChange("admin_state_up") {
		asu := d.Get("admin_state_up").(bool)
		updateOpts.AdminStateUp = &asu
	}
	if d.HasChange("listener") {
		v, err := expandOctaviaListenersUpdateV2(d.Get("listener"))
		if err != nil {
			return err
		}
		updateOpts.Listeners = &v
	}

	if updateOpts != (loadbalancers.UpdateOpts{}) {
		// Wait for load-balancer to become active before continuing.
		timeout := d.Timeout(schema.TimeoutUpdate)
		err = waitForLBV2LoadBalancer(lbClient, d.Id(), "ACTIVE", lbPendingStatuses, timeout)
		if err != nil {
			return err
		}

		log.Printf("[DEBUG] Updating openstack_lb_loadbalancer_v2 %s with options: %#v", d.Id(), updateOpts)
		err = resource.Retry(timeout, func() *resource.RetryError {
			_, err = loadbalancers.Update(lbClient, d.Id(), updateOpts).Extract()
			if err != nil {
				return checkForRetryableError(err)
			}
			return nil
		})

		if err != nil {
			return fmt.Errorf("Error updating openstack_lb_loadbalancer_v2 %s: %s", d.Id(), err)
		}

		// Wait for load-balancer to become active before continuing.
		err = waitForLBV2LoadBalancer(lbClient, d.Id(), "ACTIVE", lbPendingStatuses, timeout)
		if err != nil {
			return err
		}
	}

	// Security Groups get updated separately.
	if d.HasChange("security_group_ids") {
		networkingClient, err := config.NetworkingV2Client(GetRegion(d, config))
		if err != nil {
			return fmt.Errorf("Error creating OpenStack networking client: %s", err)
		}
		vipPortID := d.Get("vip_port_id").(string)
		if err := resourceLoadBalancerV2SetSecurityGroups(networkingClient, vipPortID, d); err != nil {
			return fmt.Errorf("Error setting openstack_lb_loadbalancer_v2 security groups: %s", err)
		}
	}

	return resourceOctaviaV2Read(d, meta)
}

func resourceOctaviaV2Delete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	lbClient, err := chooseLBV2Client(d, config)
	if err != nil {
		return fmt.Errorf("Error creating OpenStack networking client: %s", err)
	}

	log.Printf("[DEBUG] Deleting openstack_lb_loadbalancer_v2 %s", d.Id())
	timeout := d.Timeout(schema.TimeoutDelete)
	err = resource.Retry(timeout, func() *resource.RetryError {
		err = loadbalancers.Delete(lbClient, d.Id(), loadbalancers.DeleteOpts{Cascade: true}).ExtractErr()
		if err != nil {
			return checkForRetryableError(err)
		}
		return nil
	})

	if err != nil {
		return CheckDeleted(d, err, "Error deleting openstack_lb_loadbalancer_v2")
	}

	// Wait for load-balancer to become deleted.
	err = waitForLBV2LoadBalancer(lbClient, d.Id(), "DELETED", lbPendingDeleteStatuses, timeout)
	if err != nil {
		return err
	}

	return nil
}

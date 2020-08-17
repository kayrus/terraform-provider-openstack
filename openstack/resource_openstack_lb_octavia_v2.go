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
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
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
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
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
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Resource{
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
										},
									},
								},
							},
						},
					},
				},
			},

			"pool": {
				Type:     schema.TypeSet,
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

func resourceOctaviaExpandPoolPersistenceV2(raw interface{}) (*pools.SessionPersistence, error) {
	var persistence pools.SessionPersistence

	if raw != nil {
		if v, ok := raw.([]interface{}); ok {
			for _, v := range v {
				if v, ok := v.(map[string]interface{}); ok {
					persistence = pools.SessionPersistence{
						Type: v["type"].(string),
					}

					if persistence.Type == "APP_COOKIE" {
						if v["cookie_name"].(string) == "" {
							return nil, fmt.Errorf(
								"Persistence cookie_name needs to be set if using 'APP_COOKIE' persistence type.")
						} else {
							persistence.CookieName = v["cookie_name"].(string)
						}
					} else {
						if v["cookie_name"].(string) != "" {
							return nil, fmt.Errorf(
								"Persistence cookie_name can only be set if using 'APP_COOKIE' persistence type.")
						}
					}
				}
			}
		}
	}

	return &persistence, nil
}

func expandPoolV2(v map[string]interface{}) (*pools.CreateOpts, error) {
	var p pools.CreateOpts

	if v, ok := v["name"]; ok {
		p.Name = v.(string)
	}
	if v, ok := v["description"]; ok {
		p.Description = v.(string)
	}
	if v, ok := v["protocol"]; ok {
		p.Protocol = pools.Protocol(v.(string))
	}
	if v, ok := v["lb_method"]; ok {
		p.LBMethod = pools.LBMethod(v.(string))
	}
	if v, ok := v["persistence"]; ok {
		v, err := resourceOctaviaExpandPoolPersistenceV2(v)
		if err != nil {
			return nil, err
		}
		p.Persistence = v
	}
	if v, ok := v["admin_state_up"]; ok {
		v := v.(bool)
		p.AdminStateUp = &v
	}
	if v, ok := v["member"]; ok {
		if v, ok := v.(*schema.Set); ok {
			p.Members = expandLBMembersV2(v)
		}
	}
	if v, ok := v["monitor"]; ok {
		if v, ok := v.([]interface{}); ok {
			for _, v := range v {
				/*
					if v, ok := v.(*schema.Set); ok {
						for _, v := range v.List() {
				*/
				v, err := expandMonitorV2(v.(map[string]interface{}))
				if err != nil {
					return nil, err
				}
				p.Monitor = v
			}
		}
	}

	return &p, nil
}

func resourceOctaviaExpandPoolV2(raw interface{}) ([]pools.CreateOpts, error) {
	if raw != nil {
		if v, ok := raw.(*schema.Set); ok {
			var res []pools.CreateOpts

			for _, v := range v.List() {
				if v, ok := v.(map[string]interface{}); ok {
					p, err := expandPoolV2(v)
					if err != nil {
						return nil, err
					}

					res = append(res, *p)
				}
			}

			return res, nil
		}
	}

	return nil, nil
}

func resourceOctaviaExpandListenerV2(raw interface{}) ([]listeners.CreateOpts, error) {
	if raw != nil {
		if v, ok := raw.(*schema.Set); ok {
			var res []listeners.CreateOpts

			for _, v := range v.List() {
				if v, ok := v.(map[string]interface{}); ok {
					p, err := expandListenerV2(v)
					if err != nil {
						return nil, err
					}

					res = append(res, *p)
				}
			}

			return res, nil
		}
	}

	return nil, nil
}

func expandListenerV2(v map[string]interface{}) (*listeners.CreateOpts, error) {
	var p listeners.CreateOpts

	if v, ok := v["protocol"]; ok {
		p.Protocol = listeners.Protocol(v.(string))
	}
	if v, ok := v["protocol_port"]; ok {
		p.ProtocolPort = v.(int)
	}
	if v, ok := v["name"]; ok {
		p.Name = v.(string)
	}
	if v, ok := v["description"]; ok {
		p.Description = v.(string)
	}
	if v, ok := v["default_pool"]; ok {
		var err error
		if v, ok := v.(map[string]interface{}); ok {
			p.DefaultPool, err = expandPoolV2(v)
			if err != nil {
				return nil, err
			}
		}
	}
	if v, ok := v["connection_limit"]; ok {
		v := v.(int)
		p.ConnLimit = &v
	}
	if v, ok := v["default_tls_container_ref"]; ok {
		p.DefaultTlsContainerRef = v.(string)
	}
	if v, ok := v["sni_container_refs"]; ok {
		v := expandToStringSlice(v.([]interface{}))
		p.SniContainerRefs = v
	}
	if v, ok := v["admin_state_up"]; ok {
		v := v.(bool)
		p.AdminStateUp = &v
	}
	if v, ok := v["timeout_client_data"]; ok {
		v := v.(int)
		p.TimeoutClientData = &v
	}
	if v, ok := v["timeout_member_connect"]; ok {
		v := v.(int)
		p.TimeoutMemberConnect = &v
	}
	if v, ok := v["timeout_member_data"]; ok {
		v := v.(int)
		p.TimeoutMemberData = &v
	}
	if v, ok := v["timeout_tcp_inspect"]; ok {
		v := v.(int)
		p.TimeoutTCPInspect = &v
	}
	if v, ok := v["insert_headers"]; ok {
		p.InsertHeaders = expandToMapStringString(v.(map[string]interface{}))
	}
	if v, ok := v["allowed_cidrs"]; ok {
		p.AllowedCIDRs = expandToStringSlice(v.([]interface{}))
	}
	if v, ok := v["l7policy"]; ok {
		if v, ok := v.(*schema.Set); ok {
			var l7pol []l7policies.CreateOpts

			for _, v := range v.List() {
				if v, ok := v.(map[string]interface{}); ok {
					v, err := expandL7PolicyV2(v)
					if err != nil {
						return nil, err
					}
					l7pol = append(l7pol, *v)
				}
			}

			p.L7Policies = l7pol
		}
	}
	return &p, nil
}

func expandL7PolicyV2(v map[string]interface{}) (*l7policies.CreateOpts, error) {
	var p l7policies.CreateOpts

	if v, ok := v["name"]; ok {
		p.Name = v.(string)
	}
	if v, ok := v["description"]; ok {
		p.Description = v.(string)
	}
	if v, ok := v["action"]; ok {
		p.Action = l7policies.Action(v.(string))
	}
	if v, ok := v["position"]; ok {
		p.Position = int32(v.(int))
	}
	if v, ok := v["redirect_pool_id"]; ok {
		p.RedirectPoolID = v.(string)
	}
	if v, ok := v["redirect_url"]; ok {
		p.RedirectURL = v.(string)
	}
	if v, ok := v["admin_state_up"]; ok {
		v := v.(bool)
		p.AdminStateUp = &v
	}
	if v, ok := v["l7rule"]; ok {
		if v, ok := v.(*schema.Set); ok {
			var l7rule []l7policies.CreateRuleOpts

			for _, v := range v.List() {
				if v, ok := v.(map[string]interface{}); ok {
					v, err := expandL7RuleV2(v)
					if err != nil {
						return nil, err
					}
					l7rule = append(l7rule, *v)
				}
			}

			p.Rules = l7rule
		}
	}
	return &p, nil
}

func expandL7RuleV2(v map[string]interface{}) (*l7policies.CreateRuleOpts, error) {
	var p l7policies.CreateRuleOpts

	if v, ok := v["type"]; ok {
		p.RuleType = l7policies.RuleType(v.(string))
	}
	if v, ok := v["compare_type"]; ok {
		p.CompareType = l7policies.CompareType(v.(string))
	}
	if v, ok := v["value"]; ok {
		p.Value = v.(string)
	}
	if v, ok := v["key"]; ok {
		p.Key = v.(string)
	}
	if v, ok := v["invert"]; ok {
		p.Invert = v.(bool)
	}
	if v, ok := v["admin_state_up"]; ok {
		v := v.(bool)
		p.AdminStateUp = &v
	}
	return &p, nil
}

func expandMonitorV2(v map[string]interface{}) (*monitors.CreateOpts, error) {
	var p monitors.CreateOpts

	if v, ok := v["name"]; ok {
		p.Name = v.(string)
	}
	if v, ok := v["type"]; ok {
		p.Type = v.(string)
	}
	if v, ok := v["delay"]; ok {
		p.Delay = v.(int)
	}
	if v, ok := v["timeout"]; ok {
		p.Timeout = v.(int)
	}
	if v, ok := v["max_retries"]; ok {
		p.MaxRetries = v.(int)
	}
	if v, ok := v["max_retries_down"]; ok {
		p.MaxRetriesDown = v.(int)
	}
	if v, ok := v["url_path"]; ok {
		p.URLPath = v.(string)
	}
	if v, ok := v["http_method"]; ok {
		p.HTTPMethod = v.(string)
	}
	if v, ok := v["expected_codes"]; ok {
		p.ExpectedCodes = v.(string)
	}
	if v, ok := v["admin_state_up"]; ok {
		v := v.(bool)
		p.AdminStateUp = &v
	}
	return &p, nil
}

func resourceOctaviaExpandDefaultPoolV2(raw interface{}) (*pools.CreateOpts, error) {
	if raw != nil {
		if v, ok := raw.([]interface{}); ok {
			for _, v := range v {
				if v, ok := v.(map[string]interface{}); ok {
					return expandPoolV2(v)
				}
			}
		}
	}

	return nil, nil
}

func flattenOctaviaListenerV2(l listeners.Listener) []map[string]interface{} {
	var p []map[string]interface{}
	if l.DefaultPool != nil {
		p = flattenOctaviaPoolV2(*l.DefaultPool)
	}
	return []map[string]interface{}{
		{
			"name":                      l.Name,
			"description":               l.Description,
			"protocol":                  l.Protocol,
			"protocol_port":             l.ProtocolPort,
			"default_pool":              p,
			"connection_limit":          l.ConnLimit,
			"default_tls_container_ref": l.DefaultTlsContainerRef,
			"sni_container_refs":        l.SniContainerRefs,
			"admin_state_up":            l.AdminStateUp,
			"timeout_client_data":       l.TimeoutClientData,
			"timeout_member_connect":    l.TimeoutMemberConnect,
			"timeout_member_data":       l.TimeoutMemberData,
			"timeout_tcp_inspect":       l.TimeoutTCPInspect,
			"insert_headers":            l.InsertHeaders,
			"allowed_cidrs":             l.AllowedCIDRs,
			"l7policy":                  flattenOctaviaL7PolicyV2(l.L7Policies),
		},
	}
}

func flattenOctaviaL7PolicyV2(p []l7policies.L7Policy) []map[string]interface{} {
	r := make([]map[string]interface{}, len(p))
	for i, v := range p {
		r[i] = map[string]interface{}{
			"name":             v.Name,
			"description":      v.Description,
			"action":           v.Action,
			"position":         v.Position,
			"redirect_pool_id": v.RedirectPoolID,
			"redirect_url":     v.RedirectURL,
			"admin_state_up":   v.AdminStateUp,
			"l7rule":           flattenOctaviaL7RuleV2(v.Rules),
		}
	}
	return r
}

func flattenOctaviaL7RuleV2(p []l7policies.Rule) []map[string]interface{} {
	r := make([]map[string]interface{}, len(p))
	for i, v := range p {
		r[i] = map[string]interface{}{
			"type":           v.RuleType,
			"compare_type":   v.CompareType,
			"value":          v.Value,
			"key":            v.Key,
			"invert":         v.Invert,
			"admin_state_up": v.AdminStateUp,
		}
	}
	return r
}

func flattenOcrtaviaPoolPersistenceV2(p pools.SessionPersistence) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"type":        p.Type,
			"cookie_name": p.CookieName,
		},
	}
}

func flattenOctaviaPoolV2(p pools.Pool) []map[string]interface{} {
	m := flattenOctaviaMonitorV2(p.Monitor)
	log.Printf("[DEBUG] kayrus MONITOR: %+#v", m)
	return []map[string]interface{}{
		{
			"name":           p.Name,
			"description":    p.Description,
			"protocol":       p.Protocol,
			"lb_method":      p.LBMethod,
			"persistence":    flattenOcrtaviaPoolPersistenceV2(p.Persistence),
			"admin_state_up": p.AdminStateUp,
			"member":         flattenLBMembersV2(p.Members),
			"monitor":        m, //flattenOctaviaMonitorV2(p.Monitor),
		},
	}
}

func flattenOctaviaMonitorV2(m monitors.Monitor) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":             m.Name,
			"type":             m.Type,
			"delay":            m.Delay,
			"timeout":          m.Timeout,
			"max_retries":      m.MaxRetries,
			"max_retries_down": m.MaxRetriesDown,
			"url_path":         m.URLPath,
			"http_method":      m.HTTPMethod,
			"expected_codes":   m.ExpectedCodes,
			"admin_state_up":   m.AdminStateUp,
		},
	}
}

// chooseLBV2LoadBalancerCreateOpts will determine which load balancer Create options to use:
// either the Octavia/LBaaS or the Neutron/Networking v2.
func V2OctaviaCreateOpts(d *schema.ResourceData, config *Config) (*loadbalancers.CreateOpts, error) {
	var lbProvider string
	if v, ok := d.GetOk("loadbalancer_provider"); ok {
		lbProvider = v.(string)
	}

	adminStateUp := d.Get("admin_state_up").(bool)
	pool, err := resourceOctaviaExpandPoolV2(d.Get("pool"))
	if err != nil {
		return nil, err
	}

	listener, err := resourceOctaviaExpandListenerV2(d.Get("listener"))
	if err != nil {
		return nil, err
	}

	return &loadbalancers.CreateOpts{
		Name:         d.Get("name").(string),
		Description:  d.Get("description").(string),
		VipNetworkID: d.Get("vip_network_id").(string),
		VipSubnetID:  d.Get("vip_subnet_id").(string),
		ProjectID:    d.Get("tenant_id").(string),
		VipAddress:   d.Get("vip_address").(string),
		AdminStateUp: &adminStateUp,
		FlavorID:     d.Get("flavor_id").(string),
		Provider:     lbProvider,
		Pools:        pool,
		Listeners:    listener,
	}, nil
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
	createOpts, err := V2OctaviaCreateOpts(d, config)
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

package openstack

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/l7policies"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/pools"
)

func expandOctaviaPoolPersistenceV2(raw interface{}) (*pools.SessionPersistence, error) {
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

func expandOctaviaPoolCreateV2(v map[string]interface{}) (*pools.CreateOpts, error) {
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
		v, err := expandOctaviaPoolPersistenceV2(v)
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
		p.Members = expandOctaviaMembersUpdateV2(v)
	}
	if v, ok := v["monitor"]; ok {
		if v, ok := v.([]interface{}); ok {
			for _, v := range v {
				/*
					if v, ok := v.(*schema.Set); ok {
						for _, v := range v.List() {
				*/
				v, err := expandOctaviaMonitorCreateV2(v.(map[string]interface{}))
				if err != nil {
					return nil, err
				}
				p.Monitor = v
			}
		}
	}

	return &p, nil
}

func expandOctaviaPoolUpdateV2(v map[string]interface{}) (*pools.UpdateOpts, error) {
	var p pools.UpdateOpts

	if v, ok := v["name"]; ok {
		v := v.(string)
		p.Name = &v
	}
	if v, ok := v["description"]; ok {
		v := v.(string)
		p.Description = &v
	}
	/*
		if v, ok := v["protocol"]; ok {
			v := pools.Protocol(v.(string))
			p.Protocol = &v
		}
	*/
	if v, ok := v["lb_method"]; ok {
		p.LBMethod = pools.LBMethod(v.(string))
	}
	if v, ok := v["persistence"]; ok {
		v, err := expandOctaviaPoolPersistenceV2(v)
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
		v := expandOctaviaMembersUpdateV2(v)
		p.Members = &v
	}
	if v, ok := v["monitor"]; ok {
		if v, ok := v.([]interface{}); ok {
			for _, v := range v {
				/*
					if v, ok := v.(*schema.Set); ok {
						for _, v := range v.List() {
				*/
				v, err := expandOctaviaMonitorUpdateV2(v.(map[string]interface{}))
				if err != nil {
					return nil, err
				}
				p.Monitor = v
			}
		}
	}

	return &p, nil
}

func expandOctaviaMembersUpdateV2(raw interface{}) []pools.BatchUpdateMemberOpts {
	var m []pools.BatchUpdateMemberOpts

	if raw != nil {
		if v, ok := raw.(*schema.Set); ok {
			for _, raw := range v.List() {
				/*
					if v, ok := raw.([]interface{}); ok {
						for _, raw := range v {
				*/
				rawMap := raw.(map[string]interface{})
				name := rawMap["name"].(string)
				subnetID := rawMap["subnet_id"].(string)
				weight := rawMap["weight"].(int)
				adminStateUp := rawMap["admin_state_up"].(bool)

				member := pools.BatchUpdateMemberOpts{
					Address:      rawMap["address"].(string),
					ProtocolPort: rawMap["protocol_port"].(int),
					Name:         &name,
					Weight:       &weight,
					AdminStateUp: &adminStateUp,
				}

				if subnetID != "" {
					member.SubnetID = &subnetID
				}

				m = append(m, member)
			}
		}
	}

	return m
}

func expandOctaviaPoolsCreateV2(raw interface{}) ([]pools.CreateOpts, error) {
	if raw != nil {
		/*
			if v, ok := raw.(*schema.Set); ok {
				var res []pools.CreateOpts
				for _, v := range v.List() {
		*/
		if v, ok := raw.([]interface{}); ok {
			var res []pools.CreateOpts
			for _, v := range v {
				if v, ok := v.(map[string]interface{}); ok {
					p, err := expandOctaviaPoolCreateV2(v)
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

func expandOctaviaListenersCreateV2(raw interface{}) ([]listeners.CreateOpts, error) {
	if raw != nil {
		/*
			if v, ok := raw.(*schema.Set); ok {
				var res []listeners.CreateOpts

				for _, v := range v.List() {
		*/
		if v, ok := raw.([]interface{}); ok {
			var res []listeners.CreateOpts

			for _, v := range v {
				if v, ok := v.(map[string]interface{}); ok {
					p, err := expandOctaviaListenerCreateV2(v)
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

func expandOctaviaListenersUpdateV2(raw interface{}) ([]listeners.UpdateOpts, error) {
	if raw != nil {
		/*
			if v, ok := raw.(*schema.Set); ok {
				var res []listeners.CreateOpts

				for _, v := range v.List() {
		*/
		if v, ok := raw.([]interface{}); ok {
			var res []listeners.UpdateOpts

			for _, v := range v {
				if v, ok := v.(map[string]interface{}); ok {
					p, err := expandOctaviaListenerUpdateV2(v)
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

func expandOctaviaListenerUpdateV2(v map[string]interface{}) (*listeners.UpdateOpts, error) {
	var p listeners.UpdateOpts

	/*
		if v, ok := v["protocol"]; ok {
			p.Protocol = listeners.Protocol(v.(string))
		}
		if v, ok := v["protocol_port"]; ok {
			p.ProtocolPort = v.(int)
		}
	*/
	if v, ok := v["name"]; ok {
		v := v.(string)
		p.Name = &v
	}
	if v, ok := v["description"]; ok {
		v := v.(string)
		p.Description = &v
	}
	if v, ok := v["default_pool"]; ok {
		var err error
		if v, ok := v.(map[string]interface{}); ok {
			p.DefaultPool, err = expandOctaviaPoolUpdateV2(v)
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
		v := v.(string)
		p.DefaultTlsContainerRef = &v
	}
	if v, ok := v["sni_container_refs"]; ok {
		v := expandToStringSlice(v.([]interface{}))
		p.SniContainerRefs = &v
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
		v := expandToMapStringString(v.(map[string]interface{}))
		p.InsertHeaders = &v
	}
	if v, ok := v["allowed_cidrs"]; ok {
		v := expandToStringSlice(v.([]interface{}))
		p.AllowedCIDRs = &v
	}
	if v, ok := v["l7policy"]; ok {
		/*
			if v, ok := v.(*schema.Set); ok {
				var l7pol []l7policies.UpdateOpts

				for _, v := range v.List() {
		*/
		if v, ok := v.([]interface{}); ok {
			var l7pol []l7policies.UpdateOpts

			for _, v := range v {
				if v, ok := v.(map[string]interface{}); ok {
					v, err := expandOctaviaL7PolicyUpdateV2(v)
					if err != nil {
						return nil, err
					}
					l7pol = append(l7pol, *v)
				}
			}

			p.L7Policies = &l7pol
		}
	}
	return &p, nil
}

func expandOctaviaListenerCreateV2(v map[string]interface{}) (*listeners.CreateOpts, error) {
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
			p.DefaultPool, err = expandOctaviaPoolCreateV2(v)
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
		/*
			if v, ok := v.(*schema.Set); ok {
				var l7pol []l7policies.CreateOpts

				for _, v := range v.List() {
		*/
		if v, ok := v.([]interface{}); ok {
			var l7pol []l7policies.CreateOpts

			for _, v := range v {
				if v, ok := v.(map[string]interface{}); ok {
					v, err := expandOctaviaL7PolicyCreateV2(v)
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

func expandOctaviaL7PolicyCreateV2(v map[string]interface{}) (*l7policies.CreateOpts, error) {
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
		/*
			if v, ok := v.(*schema.Set); ok {
				var l7rule []l7policies.CreateRuleOpts

				for _, v := range v.List() {
		*/
		if v, ok := v.([]interface{}); ok {
			var l7rule []l7policies.CreateRuleOpts

			for _, v := range v {
				if v, ok := v.(map[string]interface{}); ok {
					v, err := expandOctaviaL7RuleCreateV2(v)
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

func expandOctaviaL7PolicyUpdateV2(v map[string]interface{}) (*l7policies.UpdateOpts, error) {
	var p l7policies.UpdateOpts

	if v, ok := v["name"]; ok {
		v := v.(string)
		p.Name = &v
	}
	if v, ok := v["description"]; ok {
		v := v.(string)
		p.Description = &v
	}
	if v, ok := v["action"]; ok {
		p.Action = l7policies.Action(v.(string))
	}
	if v, ok := v["position"]; ok {
		p.Position = int32(v.(int))
	}
	if v, ok := v["redirect_pool_id"]; ok {
		v := v.(string)
		p.RedirectPoolID = &v
	}
	if v, ok := v["redirect_url"]; ok {
		v := v.(string)
		p.RedirectURL = &v
	}
	if v, ok := v["admin_state_up"]; ok {
		v := v.(bool)
		p.AdminStateUp = &v
	}
	if v, ok := v["l7rule"]; ok {
		/*
			if v, ok := v.(*schema.Set); ok {
				var l7rule []l7policies.UpdateRuleOpts

				for _, v := range v.List() {
		*/
		if v, ok := v.([]interface{}); ok {
			var l7rule []l7policies.UpdateRuleOpts

			for _, v := range v {
				if v, ok := v.(map[string]interface{}); ok {
					v, err := expandOctaviaL7RuleUpdateV2(v)
					if err != nil {
						return nil, err
					}
					l7rule = append(l7rule, *v)
				}
			}

			p.Rules = &l7rule
		}
	}
	return &p, nil
}

func expandOctaviaL7RuleCreateV2(v map[string]interface{}) (*l7policies.CreateRuleOpts, error) {
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

func expandOctaviaL7RuleUpdateV2(v map[string]interface{}) (*l7policies.UpdateRuleOpts, error) {
	var p l7policies.UpdateRuleOpts

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
		v := v.(string)
		p.Key = &v
	}
	if v, ok := v["invert"]; ok {
		v := v.(bool)
		p.Invert = &v
	}
	if v, ok := v["admin_state_up"]; ok {
		v := v.(bool)
		p.AdminStateUp = &v
	}
	return &p, nil
}

func expandOctaviaMonitorCreateV2(v map[string]interface{}) (*monitors.CreateOpts, error) {
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

func expandOctaviaMonitorUpdateV2(v map[string]interface{}) (*monitors.UpdateOpts, error) {
	var p monitors.UpdateOpts

	if v, ok := v["name"]; ok {
		v := v.(string)
		p.Name = &v
	}
	/*
		if v, ok := v["type"]; ok {
			v := v.(string)
			p.Type = &v
		}
		TODO: cannot change type
	*/
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

/*
func expandOctaviaDefaultPoolCreateV2(raw interface{}) (*pools.CreateOpts, error) {
	if raw != nil {
		if v, ok := raw.([]interface{}); ok {
			for _, v := range v {
				if v, ok := v.(map[string]interface{}); ok {
					return expandOctaviaPoolCreateV2(v)
				}
			}
		}
	}

	return nil, nil
}
*/

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
	log.Printf("[DEBUG] kayrus MONITOR: %+#v", m) // TODO: remove
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
func octaviaLBCreateOptsV2(d *schema.ResourceData, config *Config) (*loadbalancers.CreateOpts, error) {
	var lbProvider string
	if v, ok := d.GetOk("loadbalancer_provider"); ok {
		lbProvider = v.(string)
	}

	adminStateUp := d.Get("admin_state_up").(bool)
	pool, err := expandOctaviaPoolsCreateV2(d.Get("pool"))
	if err != nil {
		return nil, err
	}

	listener, err := expandOctaviaListenersCreateV2(d.Get("listener"))
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

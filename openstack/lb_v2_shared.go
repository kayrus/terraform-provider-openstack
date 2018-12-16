package openstack

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/lbaas_v2/l7policies"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/lbaas_v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/lbaas_v2/loadbalancers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/lbaas_v2/monitors"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/lbaas_v2/pools"
)

// chooseLBV2Client will determine which load balacing client to use:
// Either the Octavia/LBaaS client or the Neutron/Networking v2 client.
func chooseLBV2Client(d *schema.ResourceData, config *Config) (*gophercloud.ServiceClient, error) {
	if config.useOctavia {
		return config.loadBalancerV2Client(GetRegion(d, config))
	}
	return config.networkingV2Client(GetRegion(d, config))
}

// chooseLBV2AccTestClient will determine which load balacing client to use:
// Either the Octavia/LBaaS client or the Neutron/Networking v2 client.
// This is similar to the chooseLBV2Client function but specific for acceptance
// tests.
func chooseLBV2AccTestClient(config *Config, region string) (*gophercloud.ServiceClient, error) {
	if config.useOctavia {
		return config.loadBalancerV2Client(region)
	}
	return config.networkingV2Client(region)
}

func waitForLBV2Listener(lbClient *gophercloud.ServiceClient, id string, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for listener %s to become %s.", id, target)

	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    resourceLBV2ListenerRefreshFunc(lbClient, id),
		Timeout:    timeout,
		Delay:      1 * time.Second,
		MinTimeout: 1 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			switch target {
			case "DELETED":
				return nil
			default:
				return fmt.Errorf("Error: listener %s not found: %s", id, err)
			}
		}
		return fmt.Errorf("Error waiting for listener %s to become %s: %s", id, target, err)
	}

	return nil
}

func resourceLBV2ListenerRefreshFunc(lbClient *gophercloud.ServiceClient, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		listener, err := listeners.Get(lbClient, id).Extract()
		if err != nil {
			return nil, "", err
		}

		// The listener resource has no Status attribute, so a successful Get is the best we can do
		return listener, "ACTIVE", nil
	}
}

func waitForLBV2LoadBalancer(lbClient *gophercloud.ServiceClient, id string, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for loadbalancer %s to become %s.", id, target)

	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    resourceLBV2LoadBalancerRefreshFunc(lbClient, id),
		Timeout:    timeout,
		Delay:      0,
		MinTimeout: 1 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			switch target {
			case "DELETED":
				return nil
			default:
				return fmt.Errorf("Error: loadbalancer %s not found: %s", id, err)
			}
		}
		return fmt.Errorf("Error waiting for loadbalancer %s to become %s: %s", id, target, err)
	}

	return nil
}

func resourceLBV2LoadBalancerRefreshFunc(lbClient *gophercloud.ServiceClient, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		lb, err := loadbalancers.Get(lbClient, id).Extract()
		if err != nil {
			return nil, "", err
		}

		return lb, lb.ProvisioningStatus, nil
	}
}

func waitForLBV2Member(lbClient *gophercloud.ServiceClient, poolID, memberID string, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for member %s to become %s.", memberID, target)

	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    resourceLBV2MemberRefreshFunc(lbClient, poolID, memberID),
		Timeout:    timeout,
		Delay:      1 * time.Second,
		MinTimeout: 1 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			switch target {
			case "DELETED":
				return nil
			default:
				return fmt.Errorf("Error: member %s not found: %s", memberID, err)
			}
		}
		return fmt.Errorf("Error waiting for member %s to become %s: %s", memberID, target, err)
	}

	return nil
}

func resourceLBV2MemberRefreshFunc(lbClient *gophercloud.ServiceClient, poolID, memberID string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		member, err := pools.GetMember(lbClient, poolID, memberID).Extract()
		if err != nil {
			return nil, "", err
		}

		// The member resource has no Status attribute, so a successful Get is the best we can do
		return member, "ACTIVE", nil
	}
}

func waitForLBV2Monitor(lbClient *gophercloud.ServiceClient, id string, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for monitor %s to become %s.", id, target)

	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    resourceLBV2MonitorRefreshFunc(lbClient, id),
		Timeout:    timeout,
		Delay:      1 * time.Second,
		MinTimeout: 1 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			switch target {
			case "DELETED":
				return nil
			default:
				return fmt.Errorf("Error: monitor %s not found: %s", id, err)
			}
		}
		return fmt.Errorf("Error waiting for monitor %s to become %s: %s", id, target, err)
	}

	return nil
}

func resourceLBV2MonitorRefreshFunc(lbClient *gophercloud.ServiceClient, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		monitor, err := monitors.Get(lbClient, id).Extract()
		if err != nil {
			return nil, "", err
		}

		// The monitor resource has no Status attribute, so a successful Get is the best we can do
		return monitor, "ACTIVE", nil
	}
}

func waitForLBV2Pool(lbClient *gophercloud.ServiceClient, id string, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for pool %s to become %s.", id, target)

	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    resourceLBV2PoolRefreshFunc(lbClient, id),
		Timeout:    timeout,
		Delay:      1 * time.Second,
		MinTimeout: 1 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			switch target {
			case "DELETED":
				return nil
			default:
				return fmt.Errorf("Error: pool %s not found: %s", id, err)
			}
		}
		return fmt.Errorf("Error waiting for pool %s to become %s: %s", id, target, err)
	}

	return nil
}

func resourceLBV2PoolRefreshFunc(lbClient *gophercloud.ServiceClient, poolID string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		pool, err := pools.Get(lbClient, poolID).Extract()
		if err != nil {
			return nil, "", err
		}

		// The pool resource has no Status attribute, so a successful Get is the best we can do
		return pool, "ACTIVE", nil
	}
}

func waitForLBV2viaPool(lbClient *gophercloud.ServiceClient, id string, target string, pending []string, timeout time.Duration) error {
	pool, err := pools.Get(lbClient, id).Extract()
	if err != nil {
		return err
	}

	for _, lb := range pool.Loadbalancers {
		return waitForLBV2LoadBalancer(lbClient, lb.ID, target, pending, timeout)
	}
	for _, listener := range pool.Listeners {
		return waitForLBV2LoadBalancer(lbClient, listener.ID, target, pending, timeout)
	}

	return fmt.Errorf("Neither a Load Balancer ID nor Listener ID could be determined from pool %s", pool.ID)
}

func waitForLBV2viaListener(lbClient *gophercloud.ServiceClient, id string, target string, pending []string, timeout time.Duration) error {
	lbID, err := getLBfromListener(lbClient, id)
	if err != nil {
		return err
	}
	return waitForLBV2LoadBalancer(lbClient, lbID, target, pending, timeout)
}

func getLBfromListener(lbClient *gophercloud.ServiceClient, id string) (string, error) {
	listener, err := listeners.Get(lbClient, id).Extract()
	if err != nil {
		return "", err
	}

	for _, lb := range listener.Loadbalancers {
		return lb.ID, nil
	}

	return "", fmt.Errorf("No Load Balancer found associated with listener %s", id)
}

func getLBandListenerandPoolfromMember(lbClient *gophercloud.ServiceClient, id string) (string, string, string, error) {
	log.Printf("[DEBUG] Trying to get Pool ID and Load balancer ID associated with the member %s", id)
	poolsPages, err := pools.List(lbClient, pools.ListOpts{}).AllPages()
	if err != nil {
		return "", "", "", fmt.Errorf("No Pools were found")
	}

	pools, err := pools.ExtractPools(poolsPages)
	if err != nil {
		return "", "", "", err
	}

	for _, pool := range pools {
		var lbID, listenerID string
		for _, lb := range pool.Loadbalancers {
			lbID = lb.ID
			break
		}
		for _, listener := range pool.Listeners {
			listenerID = listener.ID
			break
		}
		for _, member := range pool.Members {
			if member.ID == id {
				return lbID, listenerID, pool.ID, nil
			}
		}
	}

	return "", "", "", fmt.Errorf("No Pool found associated with member %s", id)
}

func waitForLBV2L7Policy(lbClient *gophercloud.ServiceClient, id string, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for l7policy %s to become %s.", id, target)

	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    resourceLBV2L7PolicyRefreshFunc(lbClient, id),
		Timeout:    timeout,
		Delay:      1 * time.Second,
		MinTimeout: 1 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			switch target {
			case "DELETED":
				return nil
			default:
				return fmt.Errorf("Error: l7policy %s not found: %s", id, err)
			}
		}
		return fmt.Errorf("Error waiting for l7policy %s to become %s: %s", id, target, err)
	}

	return nil
}

func resourceLBV2L7PolicyRefreshFunc(lbClient *gophercloud.ServiceClient, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		l7policy, err := l7policies.Get(lbClient, id).Extract()
		if err != nil {
			return nil, "", err
		}

		// The l7policy resource has no Status attribute, so a successful Get is the best we can do
		return l7policy, "ACTIVE", nil
	}
}

// The first best match will be returned
func getListenerandL7PolicyForL7Rule(lbClient *gophercloud.ServiceClient, id string, policyID string) (string, string, error) {
	log.Printf("[DEBUG] Trying to get Listener ID and L7 Policy ID associated with the l7rule '%s' or l7policy '%s'", id, policyID)
	lbsPages, err := loadbalancers.List(lbClient, loadbalancers.ListOpts{}).AllPages()
	if err != nil {
		return "", "", fmt.Errorf("No Load Balancers were found")
	}

	lbs, err := loadbalancers.ExtractLoadBalancers(lbsPages)
	if err != nil {
		return "", "", err
	}

	for _, lb := range lbs {
		statuses, err := loadbalancers.GetStatuses(lbClient, lb.ID).Extract()
		if err != nil {
			return "", "", err
		}
		for _, listener := range statuses.Loadbalancer.Listeners {
			for _, l7policy := range listener.L7Policies {
				if l7policy.ID == policyID {
					return listener.ID, l7policy.ID, nil
				}
				for _, l7rule := range l7policy.Rules {
					if l7rule.ID == id {
						return listener.ID, l7policy.ID, nil
					}
				}
			}
		}
	}

	return "", "", fmt.Errorf("No relationships for l7rule '%s' or l7policy '%s' were found", id, policyID)
}

func getListenerForL7Policy(lbClient *gophercloud.ServiceClient, id string) (string, error) {
	l7policy, err := l7policies.Get(lbClient, id).Extract()
	if err != nil {
		return "", fmt.Errorf("Unable to get l7policy %s: %s", id, err)
	}

	if l7policy.ListenerID == "" {
		listenerID, _, err := getListenerandL7PolicyForL7Rule(lbClient, "", id)
		return listenerID, err
	}

	return l7policy.ListenerID, err
}

func waitForLBV2L7Rule(lbClient *gophercloud.ServiceClient, policyID string, ruleID string, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for l7rule %s to become %s.", ruleID, target)
	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    resourceLBV2L7RuleRefreshFunc(lbClient, policyID, ruleID),
		Timeout:    timeout,
		Delay:      1 * time.Second,
		MinTimeout: 1 * time.Second,
	}
	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			switch target {
			case "DELETED":
				return nil
			default:
				return fmt.Errorf("Error: l7rule %s not found: %s", ruleID, err)
			}
		}
		return fmt.Errorf("Error waiting for l7rule %s to become %s: %s", ruleID, target, err)
	}
	return nil
}

func resourceLBV2L7RuleRefreshFunc(lbClient *gophercloud.ServiceClient, policyID string, ruleID string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		l7policy, err := l7policies.GetRule(lbClient, policyID, ruleID).Extract()
		if err != nil {
			return nil, "", err
		}
		// The l7policy resource has no Status attribute, so a successful Get is the best we can do
		return l7policy, "ACTIVE", nil
	}
}

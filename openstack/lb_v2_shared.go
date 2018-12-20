package openstack

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/lbaas_v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/lbaas_v2/loadbalancers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/lbaas_v2/monitors"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/lbaas_v2/pools"
)

// lbPendingStatuses are the valid statuses a LoadBalancer will be in while
// it's updating.
var lbPendingStatuses = []string{"PENDING_CREATE", "PENDING_UPDATE"}

// lbPendingDeleteStatuses are the valid statuses a LoadBalancer will be before delete
var lbPendingDeleteStatuses = []string{"ERROR", "PENDING_UPDATE", "PENDING_DELETE", "ACTIVE"}

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

func waitForLBV2Listener(lbClient *gophercloud.ServiceClient, listener *listeners.Listener, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for listener %s to become %s.", listener.ID, target)

	var refreshFunc resource.StateRefreshFunc
	if listener.ProvisioningStatus != "" {
		refreshFunc = resourceLBV2ListenerRefreshFunc(lbClient, listener.ID)
	} else {
		if len(listener.Loadbalancers) > 0 {
			lbID := listener.Loadbalancers[0].ID
			refreshFunc = resourceLBV2LoadBalancerRefreshFunc(lbClient, lbID)
		}
	}

	if refreshFunc == nil {
		return fmt.Errorf("Unable to determine how to check listener status")
	}

	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    refreshFunc,
		Timeout:    timeout,
		Delay:      1 * time.Second,
		MinTimeout: 1 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			if target == "DELETED" {
				return nil
			}
		}

		return fmt.Errorf("Error waiting for listener %s to become %s: %s", listener.ID, target, err)
	}

	return nil
}

func resourceLBV2ListenerRefreshFunc(lbClient *gophercloud.ServiceClient, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		lb, err := listeners.Get(lbClient, id).Extract()
		if err != nil {
			return nil, "", err
		}

		return lb, lb.ProvisioningStatus, nil
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

func waitForLBV2Member(lbClient *gophercloud.ServiceClient, parentPool *pools.Pool, member *pools.Member, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for member %s to become %s.", member.ID, target)

	var refreshFunc resource.StateRefreshFunc
	if member.ProvisioningStatus != "" {
		refreshFunc = resourceLBV2MemberRefreshFunc(lbClient, member.PoolID, member.ID)
	} else {
		lbID, err := lbV2FindLBIDviaPool(lbClient, parentPool)
		if err != nil {
			return err
		}

		refreshFunc = resourceLBV2LoadBalancerRefreshFunc(lbClient, lbID)
	}

	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    refreshFunc,
		Timeout:    timeout,
		Delay:      1 * time.Second,
		MinTimeout: 1 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			if target == "DELETED" {
				return nil
			}
		}

		return fmt.Errorf("Error waiting for member %s to become %s: %s", member.ID, target, err)
	}

	return nil
}

func resourceLBV2MemberRefreshFunc(lbClient *gophercloud.ServiceClient, poolID, memberID string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		member, err := pools.GetMember(lbClient, poolID, memberID).Extract()
		if err != nil {
			return nil, "", err
		}

		return member, member.ProvisioningStatus, nil
	}
}

func waitForLBV2Monitor(lbClient *gophercloud.ServiceClient, parentPool *pools.Pool, monitor *monitors.Monitor, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for monitor %s to become %s.", monitor.ID, target)

	var refreshFunc resource.StateRefreshFunc
	if monitor.ProvisioningStatus != "" {
		refreshFunc = resourceLBV2MonitorRefreshFunc(lbClient, monitor.ID)
	} else {
		lbID, err := lbV2FindLBIDviaPool(lbClient, parentPool)
		if err != nil {
			return err
		}

		refreshFunc = resourceLBV2LoadBalancerRefreshFunc(lbClient, lbID)
	}

	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    refreshFunc,
		Timeout:    timeout,
		Delay:      1 * time.Second,
		MinTimeout: 1 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			if target == "DELETED" {
				return nil
			}
		}
		return fmt.Errorf("Error waiting for monitor %s to become %s: %s", monitor.ID, target, err)
	}

	return nil
}

func resourceLBV2MonitorRefreshFunc(lbClient *gophercloud.ServiceClient, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		monitor, err := monitors.Get(lbClient, id).Extract()
		if err != nil {
			return nil, "", err
		}

		return monitor, monitor.ProvisioningStatus, nil
	}
}

func waitForLBV2Pool(lbClient *gophercloud.ServiceClient, pool *pools.Pool, target string, pending []string, timeout time.Duration) error {
	log.Printf("[DEBUG] Waiting for pool %s to become %s.", pool.ID, target)

	var refreshFunc resource.StateRefreshFunc
	if pool.ProvisioningStatus != "" {
		refreshFunc = resourceLBV2PoolRefreshFunc(lbClient, pool.ID)
	} else {
		lbID, err := lbV2FindLBIDviaPool(lbClient, pool)
		if err != nil {
			return err
		}

		refreshFunc = resourceLBV2LoadBalancerRefreshFunc(lbClient, lbID)
	}

	stateConf := &resource.StateChangeConf{
		Target:     []string{target},
		Pending:    pending,
		Refresh:    refreshFunc,
		Timeout:    timeout,
		Delay:      1 * time.Second,
		MinTimeout: 1 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			if target == "DELETED" {
				return nil
			}
		}

		return fmt.Errorf("Error waiting for pool %s to become %s: %s", pool.ID, target, err)
	}

	return nil
}

func resourceLBV2PoolRefreshFunc(lbClient *gophercloud.ServiceClient, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		pool, err := pools.Get(lbClient, id).Extract()
		if err != nil {
			return nil, "", err
		}

		return pool, pool.ProvisioningStatus, nil
	}
}

func lbV2FindLBIDviaPool(lbClient *gophercloud.ServiceClient, pool *pools.Pool) (string, error) {
	if len(pool.Loadbalancers) > 0 {
		return pool.Loadbalancers[0].ID, nil
	}

	if len(pool.Listeners) > 0 {
		listenerID := pool.Listeners[0].ID
		listener, err := listeners.Get(lbClient, listenerID).Extract()
		if err != nil {
			return "", err
		}

		if len(listener.Loadbalancers) > 0 {
			return listener.Loadbalancers[0].ID, nil
		}
	}

	return "", fmt.Errorf("Unable to determine loadbalancer ID from pool %s", pool.ID)
}

// Function to detect the LB element provisioning status
func lbV2GetProvisioningStatus(lbClient *gophercloud.ServiceClient,
	statusFunc func(*gophercloud.ServiceClient, *string) (interface{}, string, error),
	id string,
	lbID *string,
	target string) (interface{}, string, error) {

	log.Printf("[DEBUG] Detecting LBaaSv2 status for the %s using the %s client", id, lbClient.Type)

	res, status, err := statusFunc(lbClient, lbID)
	if status != "" {
		return res, status, err
	}

	log.Printf("[DEBUG] %s, falling back to resolve function", err)

	if lbID != nil && *lbID != "" {
		return lbV2GetProvisioningStatusViaLB(lbClient, id, *lbID)
	}

	log.Printf("[DEBUG] %s, falling back to heavy resolve function", err)

	// Heavy API calls begin
	lbsPages, err := loadbalancers.List(lbClient, loadbalancers.ListOpts{}).AllPages()
	if err != nil {
		return nil, "", fmt.Errorf("Failed to list Load Balancers: %s", err)
	}

	lbs, err := loadbalancers.ExtractLoadBalancers(lbsPages)
	if err != nil {
		return nil, "", fmt.Errorf("Failed to extract Load Balancers list into the object: %s", err)
	}

	for _, lb := range lbs {
		// Query each Load Balancer we have
		res, status, err := lbV2GetProvisioningStatusViaLB(lbClient, id, lb.ID)
		if err == nil {
			if lbID != nil {
				*lbID = lb.ID
				// Cache parent Load Balancer ID
				log.Printf("[DEBUG] Cached %s Load Balancer ID", *lbID)
			}
			return res, status, nil
		}
		log.Printf("[DEBUG] %s", err)
	}

	err404 := gophercloud.ErrDefault404{
		gophercloud.ErrUnexpectedResponseCode{
			BaseError: gophercloud.BaseError{
				DefaultErrString: fmt.Sprintf("No %s resource found", id)},
		},
	}

	return nil, "", err404
}

func lbV2GetProvisioningStatusViaLB(lbClient *gophercloud.ServiceClient, id string, lbID string) (interface{}, string, error) {
	log.Printf("[DEBUG] Trying to detect %s object status from the Load Balancer %s statuses tree", id, lbID)
	statuses, err := loadbalancers.GetStatuses(lbClient, lbID).Extract()
	if err != nil {
		return nil, "", fmt.Errorf("Unable to get statuses from the Load Balancer %s statuses tree: %s", lbID, err)
	}

	for _, listener := range statuses.Loadbalancer.Listeners {
		if listener.ID == id {
			if listener.ProvisioningStatus == "" {
				log.Printf("[DEBUG] Got an empty provisioning status response for the %s Listener, falling back to ACTIVE", id)
				return listener, "ACTIVE", nil
			}
			log.Printf("[DEBUG] Found %s provisioning status for the %s Listener", listener.ProvisioningStatus, id)
			return listener, listener.ProvisioningStatus, nil
		}
		/* Waiting for https://github.com/gophercloud/gophercloud/issues/1366
		for _, l7policy := range listener.L7Policies {
			if l7policy.ID == id {
				if l7policy.ProvisioningStatus == "" {
					log.Printf("[DEBUG] Got an empty provisioning status response for the %s L7 Policy, falling back to ACTIVE", id)
					return l7policy, "ACTIVE", nil
				}
				log.Printf("[DEBUG] Found %s provisioning status for the %s L7 Policy", l7policy.ProvisioningStatus, id)
				return l7policy, l7policy.ProvisioningStatus, nil
			}

			for _, l7rule := range l7policy.L7rules {
				if l7rule.ID == id {
					if l7rule.ProvisioningStatus == "" {
						log.Printf("[DEBUG] Got an empty provisioning status response for the %s L7 Rule, falling back to ACTIVE", id)
						return l7rule, "ACTIVE", nil
					}
					log.Printf("[DEBUG] Found %s provisioning status for the %s L7 Rule", l7rule.ProvisioningStatus, id)
					return l7rule, l7rule.ProvisioningStatus, nil
				}
			}
		}
		*/
	}

	/* Waiting for https://github.com/gophercloud/gophercloud/issues/1366 */
	for _, pool := range statuses.Loadbalancer.Pools {
		if pool.ID == id {
			if pool.ProvisioningStatus == "" {
				log.Printf("[DEBUG] Got an empty provisioning status response for the %s Pool, falling back to ACTIVE", id)
				return pool, "ACTIVE", nil
			}
			log.Printf("[DEBUG] Found %s provisioning status for the %s Pool", pool.ProvisioningStatus, id)
			return pool, pool.ProvisioningStatus, nil
		}

		if pool.Monitor.ID == id {
			if pool.Monitor.ProvisioningStatus == "" {
				log.Printf("[DEBUG] Got an empty provisioning status response for the %s Monitor, falling back to ACTIVE", id)
				return pool.Monitor, "ACTIVE", nil
			}
			log.Printf("[DEBUG] Found %s provisioning status for the %s Monitor", pool.Monitor.ProvisioningStatus, id)
			return pool.Monitor, pool.Monitor.ProvisioningStatus, nil
		}

		for _, member := range pool.Members {
			if member.ID == id {
				if member.ProvisioningStatus == "" {
					log.Printf("[DEBUG] Got an empty provisioning status response for the %s Member, falling back to ACTIVE", id)
					return member, "ACTIVE", nil
				}
				log.Printf("[DEBUG] Found %s provisioning status for the %s member", member.ProvisioningStatus, id)
				return member, member.ProvisioningStatus, nil
			}
		}
	}

	err404 := gophercloud.ErrDefault404{
		gophercloud.ErrUnexpectedResponseCode{
			BaseError: gophercloud.BaseError{
				DefaultErrString: fmt.Sprintf("Unable to to find the %s object from the Load Balancer %s statuses tree", id, lbID)},
		},
	}

	return nil, "", err404
}

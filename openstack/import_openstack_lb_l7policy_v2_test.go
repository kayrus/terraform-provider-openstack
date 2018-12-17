package openstack

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccLBV2L7policy_importBasic(t *testing.T) {
	l7PolicyResourceName := "openstack_lb_l7policy_v2.l7policy_1"
	listenerResourceName := "openstack_lb_listener_v2.listener_1"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheckLB(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckLBV2L7policyDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccCheckLBV2L7policyConfig_basic,
			},

			resource.TestStep{
				ResourceName:      l7PolicyResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccLBV2L7PolicyImportID(listenerResourceName, l7PolicyResourceName),
			},
		},
	})
}

func testAccLBV2L7PolicyImportID(listenerResource, l7PolicyResource string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		listener, ok := s.RootModule().Resources[listenerResource]
		if !ok {
			return "", fmt.Errorf("Listener not found: %s", listenerResource)
		}

		l7Policy, ok := s.RootModule().Resources[l7PolicyResource]
		if !ok {
			return "", fmt.Errorf("L7 Policy not found: %s", l7PolicyResource)
		}

		return fmt.Sprintf("%s/%s", listener.Primary.ID, l7Policy.Primary.ID), nil
	}
}

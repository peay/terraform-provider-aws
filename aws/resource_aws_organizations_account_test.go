package aws

import (
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/service/organizations"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func testAccAwsOrganizationsAccount_basic(t *testing.T) {
	var account organizations.Account

	test_email, ok := os.LookupEnv("TEST_AWS_ORGANIZATION_ACCOUNT_EMAIL")

	if !ok {
		t.Skip("'TEST_AWS_ORGANIZATION_ACCOUNT_EMAIL' not set, skipping test.")
	}

	name := "my_new_account"
	email := test_email

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAwsOrganizationsAccountDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAwsOrganizationsAccountConfig(name, email),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAwsOrganizationsAccountExists("aws_organizations_account.test", &account),
				),
			},
		},
	})
}

func testAccCheckAwsOrganizationsAccountDestroy(s *terraform.State) error {
	conn := testAccProvider.Meta().(*AWSClient).organizationsconn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_organizations_account" {
			continue
		}

		params := &organizations.DescribeAccountInput{
			AccountId: &rs.Primary.ID,
		}

		resp, err := conn.DescribeAccount(params)

		if err != nil || resp == nil {
			return nil
		}

		if resp.Account != nil {
			return fmt.Errorf("Bad: Account still exists: %q", rs.Primary.ID)
		}
	}

	return nil

}

func testAccCheckAwsOrganizationsAccountExists(n string, a *organizations.Account) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		conn := testAccProvider.Meta().(*AWSClient).organizationsconn
		params := &organizations.DescribeAccountInput{
			AccountId: &rs.Primary.ID,
		}

		resp, err := conn.DescribeAccount(params)

		if err != nil || resp == nil {
			return nil
		}

		if resp.Account == nil {
			return fmt.Errorf("Bad: Account %q does not exist", rs.Primary.ID)
		}

		a = resp.Account

		return nil
	}
}

func testAccAwsOrganizationsAccountConfig(name, email string) string {
	return fmt.Sprintf(`
resource "aws_organizations_account" "test" {
  name = "%s"
  email = "%s"
}
`, name, email)
}

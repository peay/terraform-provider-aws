package aws

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/emr"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

func resourceAwsEMRInstanceGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsEMRInstanceGroupCreate,
		Read:   resourceAwsEMRInstanceGroupRead,
		Update: resourceAwsEMRInstanceGroupUpdate,
		Delete: resourceAwsEMRInstanceGroupDelete,
		Importer: &schema.ResourceImporter{
			State: func(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
				idParts := strings.Split(d.Id(), "/")
				if len(idParts) != 2 || idParts[0] == "" || idParts[1] == "" {
					return nil, fmt.Errorf("Unexpected format of ID (%q), expected cluster-id/ig-id", d.Id())
				}
				clusterID := idParts[0]
				resourceID := idParts[1]
				d.Set("cluster_id", clusterID)
				d.SetId(resourceID)
				return []*schema.ResourceData{d}, nil
			},
		},
		Schema: map[string]*schema.Schema{
			"autoscaling_policy": {
				Type:             schema.TypeString,
				Optional:         true,
				DiffSuppressFunc: suppressEquivalentJsonDiffs,
				ValidateFunc:     validation.ValidateJsonString,
			},
			"bid_price": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"cluster_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"ebs_optimized": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
			},
			"ebs_config": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				ForceNew: true,
				Elem:     ebsConfigurationSchema(),
			},
			"instance_count": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  1,
			},
			"instance_type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"name": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"running_instance_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceAwsEMRInstanceGroupCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).emrconn

	instanceRole := emr.InstanceGroupTypeTask

	ebsConfig := &emr.EbsConfiguration{}
	if v, ok := d.GetOk("ebs_config"); ok && v.(*schema.Set).Len() == 1 {
		ebsConfig = expandEbsConfiguration(v.(*schema.Set).List())
	}

	if v, ok := d.GetOk("ebs_optimized"); ok {
		ebsConfig.EbsOptimized = aws.Bool(v.(bool))
	}

	params := &emr.AddInstanceGroupsInput{
		InstanceGroups: []*emr.InstanceGroupConfig{
			{
				InstanceRole:     aws.String(emr.InstanceRoleTypeTask),
				InstanceCount:    aws.Int64(int64(d.Get("instance_count").(int))),
				InstanceType:     aws.String(d.Get("instance_type").(string)),
				Name:             aws.String(d.Get("name").(string)),
				EbsConfiguration: ebsConfig,
			},
		},
		JobFlowId: aws.String(d.Get("cluster_id").(string)),
	}

	log.Printf("[DEBUG] Creating EMR %s group with the following params: %s", instanceRole, params)
	resp, err := conn.AddInstanceGroups(params)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Created EMR %s group finished: %#v", instanceRole, resp)
	if resp == nil || len(resp.InstanceGroupIds) == 0 {
		return fmt.Errorf("Error creating instance groups: no instance group returned")
	}
	d.SetId(*resp.InstanceGroupIds[0])

	return resourceAwsEMRInstanceGroupRead(d, meta)
}

func resourceAwsEMRInstanceGroupRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).emrconn

	ig, err := fetchEMRInstanceGroup(conn, d.Get("cluster_id").(string), d.Id())

	if isResourceNotFoundError(err) {
		log.Printf("[DEBUG] EMR Instance Group (%s) not found, removing", d.Id())
		d.SetId("")
		return nil
	}

	if err != nil {
		return fmt.Errorf("error reading EMR Instance Group (%s): %s", d.Id(), err)
	}

	var autoscalingPolicyString string
	if ig.AutoScalingPolicy != nil {
		// AutoScalingPolicy has an additional Status field and null values that are causing a new hashcode to be generated for `instance_group`.
		// We are purposefully omitting that field and the null values here when we flatten the autoscaling policy string for the statefile.
		for i, rule := range ig.AutoScalingPolicy.Rules {
			for j, dimension := range rule.Trigger.CloudWatchAlarmDefinition.Dimensions {
				if aws.StringValue(dimension.Key) == "JobFlowId" {
					tmpDimensions := append(ig.AutoScalingPolicy.Rules[i].Trigger.CloudWatchAlarmDefinition.Dimensions[:j], ig.AutoScalingPolicy.Rules[i].Trigger.CloudWatchAlarmDefinition.Dimensions[j+1:]...)
					ig.AutoScalingPolicy.Rules[i].Trigger.CloudWatchAlarmDefinition.Dimensions = tmpDimensions
				}
			}

			if len(ig.AutoScalingPolicy.Rules[i].Trigger.CloudWatchAlarmDefinition.Dimensions) == 0 {
				ig.AutoScalingPolicy.Rules[i].Trigger.CloudWatchAlarmDefinition.Dimensions = nil
			}
		}

		autoscalingPolicyConstraintsBytes, err := json.Marshal(ig.AutoScalingPolicy.Constraints)
		if err != nil {
			return fmt.Errorf("error parsing EMR Cluster Instance Groups AutoScalingPolicy Constraints: %s", err)
		}

		autoscalingPolicyRulesBytes, err := marshalWithoutNil(ig.AutoScalingPolicy.Rules)
		if err != nil {
			return fmt.Errorf("error parsing EMR Cluster Instance Groups AutoScalingPolicy Rules: %s", err)
		}

		autoscalingPolicyString = fmt.Sprintf("{\"Constraints\":%s,\"Rules\":%s}", string(autoscalingPolicyConstraintsBytes), string(autoscalingPolicyRulesBytes))
	}
	d.Set("autoscaling_policy", autoscalingPolicyString)

	d.Set("bid_price", ig.BidPrice)
	if err := d.Set("ebs_config", flattenEBSConfig(ig.EbsBlockDevices)); err != nil {
		return fmt.Errorf("error setting ebs_config: %s", err)
	}
	d.Set("ebs_optimized", ig.EbsOptimized)
	d.Set("instance_count", ig.RequestedInstanceCount)
	d.Set("instance_role", ig.InstanceGroupType)
	d.Set("instance_type", ig.InstanceType)
	d.Set("name", ig.Name)
	d.Set("running_instance_count", ig.RunningInstanceCount)

	if ig.Status != nil {
		d.Set("status", ig.Status.State)
	}

	return nil
}

func resourceAwsEMRInstanceGroupUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).emrconn

	log.Printf("[DEBUG] Modify EMR task group")
	if d.HasChange("instance_count") {
		instanceCount := d.Get("instance_count").(int)

		params := &emr.ModifyInstanceGroupsInput{
			InstanceGroups: []*emr.InstanceGroupModifyConfig{
				{
					InstanceGroupId: aws.String(d.Id()),
					InstanceCount:   aws.Int64(int64(instanceCount)),
				},
			},
		}

		_, err := conn.ModifyInstanceGroups(params)
		if err != nil {
			return fmt.Errorf("error modifying EMR Instance Group (%s): %s", d.Id(), err)
		}

		stateConf := &resource.StateChangeConf{
			Pending: []string{
				emr.InstanceGroupStateBootstrapping,
				emr.InstanceGroupStateProvisioning,
				emr.InstanceGroupStateResizing,
			},
			Target:     []string{emr.InstanceGroupStateRunning},
			Refresh:    instanceGroupStateRefresh(conn, d.Get("cluster_id").(string), d.Id()),
			Timeout:    10 * time.Minute,
			Delay:      10 * time.Second,
			MinTimeout: 3 * time.Second,
		}

		if _, err := stateConf.WaitForState(); err != nil {
			return fmt.Errorf("error waiting for EMR Instance Group (%s) modification: %s", d.Id(), err)
		}
	}

	if d.HasChange("autoscaling_policy") {
		var autoScalingPolicy *emr.AutoScalingPolicy

		if err := json.Unmarshal([]byte(d.Get("autoscaling_policy").(string)), &autoScalingPolicy); err != nil {
			return fmt.Errorf("error parsing EMR Auto Scaling Policy JSON for update: %s", err)
		}

		putAutoScalingPolicy := &emr.PutAutoScalingPolicyInput{
			ClusterId:         aws.String(d.Get("cluster_id").(string)),
			AutoScalingPolicy: autoScalingPolicy,
			InstanceGroupId:   aws.String(d.Id()),
		}

		if _, err := conn.PutAutoScalingPolicy(putAutoScalingPolicy); err != nil {
			return fmt.Errorf("error updating autoscaling policy for instance group %q: %s", d.Id(), err)
		}
	}

	return resourceAwsEMRInstanceGroupRead(d, meta)
}

func resourceAwsEMRInstanceGroupDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).emrconn

	log.Printf("[WARN] AWS EMR Instance Group does not support DELETE; resizing cluster to zero before removing from state")
	params := &emr.ModifyInstanceGroupsInput{
		InstanceGroups: []*emr.InstanceGroupModifyConfig{
			{
				InstanceGroupId: aws.String(d.Id()),
				InstanceCount:   aws.Int64(0),
			},
		},
	}

	if _, err := conn.ModifyInstanceGroups(params); err != nil {
		return fmt.Errorf("error draining EMR Instance Group (%s): %s", d.Id(), err)
	}
	return nil
}

func instanceGroupStateRefresh(conn *emr.EMR, clusterID, groupID string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		ig, err := fetchEMRInstanceGroup(conn, clusterID, groupID)
		if err != nil {
			return nil, "Not Found", err
		}

		if ig.Status == nil || ig.Status.State == nil {
			log.Printf("[WARN] ERM Instance Group found, but without state")
			return nil, "Undefined", fmt.Errorf("Undefined EMR Cluster Instance Group state")
		}

		return ig, *ig.Status.State, nil
	}
}

func fetchEMRInstanceGroup(conn *emr.EMR, clusterID, groupID string) (*emr.InstanceGroup, error) {
	input := &emr.ListInstanceGroupsInput{ClusterId: aws.String(clusterID)}

	var groups []*emr.InstanceGroup
	err := conn.ListInstanceGroupsPages(input, func(page *emr.ListInstanceGroupsOutput, lastPage bool) bool {
		groups = append(groups, page.InstanceGroups...)

		return !lastPage
	})

	if err != nil {
		return nil, fmt.Errorf("unable to retrieve EMR Cluster (%q): %s", clusterID, err)
	}

	if len(groups) == 0 {
		return nil, fmt.Errorf("no instance groups found for EMR Cluster (%s)", clusterID)
	}

	var ig *emr.InstanceGroup
	for _, group := range groups {
		if groupID == aws.StringValue(group.Id) {
			ig = group
			break
		}
	}

	if ig == nil {
		return nil, &resource.NotFoundError{}
	}

	return ig, nil
}

// marshalWithoutNil returns a JSON document of v stripped of any null properties
func marshalWithoutNil(v interface{}) ([]byte, error) {
	//removeNil is a helper for stripping nil values
	removeNil := func(data map[string]interface{}) map[string]interface{} {

		m := make(map[string]interface{})
		for k, v := range data {
			if v == nil {
				continue
			}

			switch v := v.(type) {
			case map[string]interface{}:
				m[k] = removeNil(v)
			default:
				m[k] = v
			}
		}

		return m
	}

	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var rules []map[string]interface{}
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}

	var cleanRules []map[string]interface{}
	for _, rule := range rules {
		cleanRules = append(cleanRules, removeNil(rule))
	}

	return json.Marshal(cleanRules)
}

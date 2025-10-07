package validate

import (
	"testing"

	"github.com/stretchr/testify/require"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLabelSelectorParsing(t *testing.T) {
	labelSelector := k8smetav1.LabelSelector{
		MatchLabels: map[string]string{
			"app": "my-app",
		},
		MatchExpressions: []k8smetav1.LabelSelectorRequirement{
			{
				Key:      "environment",
				Operator: k8smetav1.LabelSelectorOpIn,
				Values:   []string{"production", "staging"},
			},
			{
				Key:      "phase",
				Operator: k8smetav1.LabelSelectorOpNotIn,
				Values:   []string{"initial", "final"},
			},
			{
				Key:      "foo",
				Operator: k8smetav1.LabelSelectorOpExists,
				Values:   []string{},
			},
			{
				Key:      "bar",
				Operator: k8smetav1.LabelSelectorOpDoesNotExist,
				Values:   []string{},
			},
		},
	}

	labelSelectorString, err := formatLabelSelectorString(&labelSelector)
	require.NoError(t, err)
	require.Equal(t, "app=my-app,!bar,environment in (production,staging),foo,phase notin (final,initial)", labelSelectorString)
}

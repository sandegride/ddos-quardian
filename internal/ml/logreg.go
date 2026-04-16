package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
)

type LogisticModel struct {
	FeatureNames []string  `json:"feature_names"`
	Mean         []float64 `json:"mean"`
	Std          []float64 `json:"std"`
	Weights      []float64 `json:"weights"`
	Bias         float64   `json:"bias"`
	Threshold    float64   `json:"threshold"`
}

func Load(path string) (*LogisticModel, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m LogisticModel
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse model json: %w", err)
	}
	if m.Threshold <= 0 {
		m.Threshold = 0.7
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("model validation: %w", err)
	}
	return &m, nil
}

// Validate checks that all arrays in the model are consistent.
func (m *LogisticModel) Validate() error {
	n := len(m.Weights)
	if n == 0 {
		return fmt.Errorf("model has no weights")
	}
	if len(m.Mean) != n {
		return fmt.Errorf("mean length %d != weights length %d", len(m.Mean), n)
	}
	if len(m.Std) != n {
		return fmt.Errorf("std length %d != weights length %d", len(m.Std), n)
	}
	if len(m.FeatureNames) > 0 && len(m.FeatureNames) != n {
		return fmt.Errorf("feature_names length %d != weights length %d", len(m.FeatureNames), n)
	}
	return nil
}

func (m *LogisticModel) PredictProba(x []float64) float64 {
	z := m.Bias
	for i := 0; i < len(x) && i < len(m.Weights); i++ {
		xi := x[i]
		if i < len(m.Mean) && i < len(m.Std) {
			std := m.Std[i]
			if std < 1e-12 {
				// Constant feature: center but keep scale=1 so weights still apply.
				std = 1.0
			}
			xi = (xi - m.Mean[i]) / std
		}
		z += m.Weights[i] * xi
	}
	return 1.0 / (1.0 + math.Exp(-z))
}

func (m *LogisticModel) Predict(x []float64) bool {
	return m.PredictProba(x) >= m.Threshold
}

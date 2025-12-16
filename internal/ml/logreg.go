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
	return &m, nil
}

func (m *LogisticModel) PredictProba(x []float64) float64 {
	// standardize
	z := m.Bias
	for i := 0; i < len(x) && i < len(m.Weights); i++ {
		xi := x[i]
		if i < len(m.Mean) && i < len(m.Std) && m.Std[i] > 1e-12 {
			xi = (xi - m.Mean[i]) / m.Std[i]
		}
		z += m.Weights[i] * xi
	}
	return 1.0 / (1.0 + math.Exp(-z))
}

func (m *LogisticModel) Predict(x []float64) bool {
	return m.PredictProba(x) >= m.Threshold
}

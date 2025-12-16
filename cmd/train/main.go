package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"

	"ddos-detector/internal/ml"
)

func main() {
	inPath := flag.String("in", "", "Input CSV (features..., label)")
	outPath := flag.String("out", "./models/model.json", "Output model.json")
	iters := flag.Int("iters", 300, "Gradient descent iterations")
	lr := flag.Float64("lr", 0.2, "Learning rate")
	threshold := flag.Float64("threshold", 0.7, "Decision threshold")
	flag.Parse()

	if *inPath == "" {
		fmt.Println("Please provide -in dataset.csv")
		os.Exit(1)
	}

	X, y, names, err := loadCSV(*inPath)
	if err != nil {
		fmt.Println("Load error:", err)
		os.Exit(1)
	}
	mean, std := standardizeInPlace(X)

	w, b := trainLogReg(X, y, *iters, *lr)

	model := ml.LogisticModel{
		FeatureNames: names,
		Mean:         mean,
		Std:          std,
		Weights:      w,
		Bias:         b,
		Threshold:    *threshold,
	}

	os.MkdirAll(dir(*outPath), 0o755)
	f, err := os.Create(*outPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(model); err != nil {
		panic(err)
	}
	fmt.Println("Saved model to", *outPath)
}

func dir(p string) string {
	i := len(p) - 1
	for i >= 0 && p[i] != '/' && p[i] != '\\' {
		i--
	}
	if i <= 0 {
		return "."
	}
	return p[:i]
}

func loadCSV(path string) ([][]float64, []int, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	recs, err := r.ReadAll()
	if err != nil {
		return nil, nil, nil, err
	}
	if len(recs) < 2 {
		return nil, nil, nil, fmt.Errorf("not enough rows")
	}

	header := recs[0]
	if len(header) < 2 {
		return nil, nil, nil, fmt.Errorf("need >=2 columns")
	}

	// last column is label
	featNames := header[:len(header)-1]

	X := make([][]float64, 0, len(recs)-1)
	y := make([]int, 0, len(recs)-1)

	for i := 1; i < len(recs); i++ {
		row := recs[i]
		if len(row) != len(header) {
			continue
		}
		x := make([]float64, len(featNames))
		for j := 0; j < len(featNames); j++ {
			v, err := strconv.ParseFloat(row[j], 64)
			if err != nil {
				v = 0
			}
			x[j] = v
		}
		lbl, err := strconv.Atoi(row[len(header)-1])
		if err != nil {
			lbl = 0
		}
		X = append(X, x)
		y = append(y, lbl)
	}
	return X, y, featNames, nil
}

func standardizeInPlace(X [][]float64) ([]float64, []float64) {
	if len(X) == 0 {
		return nil, nil
	}
	d := len(X[0])
	mean := make([]float64, d)
	std := make([]float64, d)

	for j := 0; j < d; j++ {
		s := 0.0
		for i := 0; i < len(X); i++ {
			s += X[i][j]
		}
		mean[j] = s / float64(len(X))
	}
	for j := 0; j < d; j++ {
		s := 0.0
		for i := 0; i < len(X); i++ {
			diff := X[i][j] - mean[j]
			s += diff * diff
		}
		std[j] = math.Sqrt(s/float64(len(X)) + 1e-12)
	}
	// apply
	for i := 0; i < len(X); i++ {
		for j := 0; j < d; j++ {
			X[i][j] = (X[i][j] - mean[j]) / std[j]
		}
	}
	return mean, std
}

func trainLogReg(X [][]float64, y []int, iters int, lr float64) ([]float64, float64) {
	if len(X) == 0 {
		return nil, 0
	}
	n := len(X)
	d := len(X[0])
	w := make([]float64, d)
	b := 0.0

	sigmoid := func(z float64) float64 {
		if z < -30 {
			return 1e-13
		}
		if z > 30 {
			return 1 - 1e-13
		}
		return 1.0 / (1.0 + math.Exp(-z))
	}

	for it := 0; it < iters; it++ {
		// gradients
		gradW := make([]float64, d)
		gradB := 0.0
		loss := 0.0

		for i := 0; i < n; i++ {
			z := b
			for j := 0; j < d; j++ {
				z += w[j] * X[i][j]
			}
			p := sigmoid(z)
			yi := float64(y[i])
			// logistic loss
			loss += -(yi*math.Log(p+1e-12) + (1-yi)*math.Log(1-p+1e-12))
			diff := p - yi
			for j := 0; j < d; j++ {
				gradW[j] += diff * X[i][j]
			}
			gradB += diff
		}

		// update
		for j := 0; j < d; j++ {
			w[j] -= lr * gradW[j] / float64(n)
		}
		b -= lr * gradB / float64(n)

		if (it+1)%50 == 0 {
			fmt.Printf("iter=%d loss=%.4f\n", it+1, loss/float64(n))
		}
	}
	return w, b
}

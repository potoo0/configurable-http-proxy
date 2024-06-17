package lib

import (
	"encoding/json"
	"io"
	"net/http"
)

func WriteJson(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	bytes, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(bytes)
}

func ParseJson(body io.Reader) (map[string]any, error) {
	decoder := json.NewDecoder(body)
	data := make(map[string]any)
	err := decoder.Decode(&data)
	return data, err
}

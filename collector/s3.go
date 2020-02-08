package main

import "github.com/charles-d-burton/kanscan/shared"

type SaveToFileS3 struct {
}

func (stfs *SaveToFileS3) Create(result *shared.Scan) (bool, error) {
	return true, nil
}
func (stfs *SaveToFileS3) Update(result *shared.Scan) (bool, error) {
	return false, nil
}
func (stfs *SaveToFileS3) Delete(result *shared.Scan) (bool, error) {
	return false, nil
}

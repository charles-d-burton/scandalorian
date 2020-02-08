package main

import "github.com/charles-d-burton/kanscan/shared"

type SaveToFileSystem struct {
}

func (stfs *SaveToFileSystem) Create(result *shared.Scan) (bool, error) {
	return true, nil
}
func (stfs *SaveToFileSystem) Update(result *shared.Scan) (bool, error) {
	return false, nil
}
func (stfs *SaveToFileSystem) Delete(result *shared.Scan) (bool, error) {
	return false, nil
}

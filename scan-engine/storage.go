package main

type Storage interface {
	Push(data []byte) error
}

type S3 struct {

}

func (s3 *S3) Push(data []byte) error {
	return nil
}
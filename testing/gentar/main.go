// usage: go run main.go -d '../../../foo' < some-file > example.tar
package main

import (
	"archive/tar"
	"flag"
	"io"
	"log"
	"os"
)

func main() {
	destPath := flag.String("d", "", "The entry's file path")

	flag.Parse()

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalln(err)
	}

	tw := tar.NewWriter(os.Stdout)
	err = tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     *destPath,
		Size:     int64(len(raw)),
		Mode:     0755,
	})
	if err != nil {
		log.Fatalln(err)
	}

	_, err = tw.Write(raw)
	if err != nil {
		log.Fatalln(err)
	}

	tw.Close()
}

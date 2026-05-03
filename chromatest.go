//go:build ignore

package main

import (
	"fmt"

	"github.com/Depado/bfchroma"
	chroma_html "github.com/alecthomas/chroma/formatters/html"
	blackfriday "github.com/russross/blackfriday/v2"
)

func main() {
	md := "` + "`" + `vql\nLET aa = SELECT *, format(format='''Lorem ipsum dolor sit amet, consectetur adipiscing elit. In sit amet euismod sem. Ut maximus leo ullamcorper cursus luctus. Nam hendrerit fermentum ligula, id dictu''') FROM info()\n` + "`" + `\n"
	output := blackfriday.Run(
		[]byte(md),
		blackfriday.WithRenderer(bfchroma.NewRenderer(
			bfchroma.ChromaOptions(
				chroma_html.ClassPrefix("chroma"),
				chroma_html.WithClasses(true),
				chroma_html.WithLineNumbers(true)),
			bfchroma.Style("github"),
		)))
	fmt.Println(string(output))
}

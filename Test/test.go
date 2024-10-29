package main

import "fmt"

func main() {
	fmt.Println(add(1, 2))
}

func add(a, b int) (c int) {
	c = a + b
	return c
}

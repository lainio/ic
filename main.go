package main

import (
	"fmt"
	"os"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func test0() (err error) {
	//defer err2.Return(&err)
	defer err2.Annotatew("annnot", &err)
	//defer err2.Handle(&err, func() {
	//	fmt.Println("*** ERR:", err)
	//})

	//f := try.To1(os.Open("tsts"))
	//defer f.Close()
	panic("panic!")
	assert.NotImplemented()
	return nil
}

func test1() (err error) {
	defer err2.Returnw(&err, "test1")
	//defer err2.Annotate("annnot", &err)

	f := try.To1(os.Open("tsts"))
	defer f.Close()
	return nil
}

func test2(p []byte, ptr *int) (err error) {
	//defer err2.Returnw(&err, "")
	//defer err2.Annotate("annnot", &err)
	defer err2.Handle(&err, func() {
		fmt.Println("*** ERR:", err)
	})

	//*ptr = 1
	p[0] = 1

	return nil
}

func ter[T any](b bool, yes, no T) T {
	if b {
		return yes
	} else {
		return no
	}
}

func main() {
	defer err2.CatchTrace(func(err error) {
		fmt.Println("ERR:", err)
	})
//		defer err2.CatchAll(func(err error) {
//			fmt.Println("ERR:", err)
//		}, func(v any) {
//			fmt.Println("Panic:", v)
//		})

//	err2.StackStraceWriter = os.Stderr

	for i := 0; i < 2; i++ {
		fmt.Println("ter:", ter(i == 0, "yes", "no"))
		fmt.Println("ter:", ter(i == 0, 1, 2))
		fmt.Println("ter:", ter(i == 0, 1.01, 2.01))
	}

	//try.To(test1())
	//err2.Check(test0())
	//try.To(test0())
	try.To(test2(nil, nil))

	fmt.Println("done")
}

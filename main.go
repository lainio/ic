package main

import (
	"fmt"
	"io"
	"os"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

type TestError struct {
}

func (t *TestError) Error() string {
	return "this is test error, a own error type"
}

// CopyFile copies source file to the given destination. If any error occurs it
// returns error value describing the reason.
func CopyFile(src, dst string) (err error) {
	// Add first error handler just to annotate the error properly by using new
	// automatic annotation mechanism.
	defer err2.Handle(&err)

	// Try to open the file. If error occurs now, err will be annotated and
	// returned properly thanks to above err2.Returnf.
	r := try.To1(os.Open(src))
	defer r.Close()

	// Try to create a file. If error occurs now, err will be annotated and
	// returned properly.
	//w := try.To1(os.Create(dst))
	w, err :=os.Create(dst)
	if err != nil {
		return fmt.Errorf("TEST: %v", err)
	}
	// Add error handler to clean up the destination file. Place it here that
	// the next deferred close is called before our Remove call.
	defer err2.Handle(&err, func() {
		fmt.Println("cleaning target file")
		os.Remove(dst)
		err = new(TestError) // TestError is concrete type
	})
	defer w.Close()

	// Try to copy the file. If error occurs now, all previous error handlers
	// will be called in the reversed order. And final return error is
	// properly annotated in all the cases.
	//try.To1(io.Copy(w, r))
	try.To1(errCopy(w, r))

	// All OK, just return nil.
	return nil
}

func errCopy(w io.Writer, r io.Reader) (n int64, err error) {
	return 0, fmt.Errorf("cannot write file")
}

func test0() (err error) {
	//defer err2.Return(&err)
	defer err2.Returnw(&err, "annnot")
	//defer err2.Handle(&err, func() {
	//	fmt.Println("*** ERR:", err)
	//})

	//f := try.To1(os.Open("tsts"))
	//defer f.Close()
	assert.NotImplemented()
	return nil
}

func test1() (err error) {
	defer err2.Returnf(&err, "test1")
	//defer err2.Returnf(&err, "annnot")

	f := try.To1(os.Open("tsts"))
	defer f.Close()
	return nil
}

func test2(p []byte, ptr *int) (err error) {
	//defer err2.Returnw(&err, "")
	//defer err2.Returnf(&err, "annnot")
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
	err2.SetErrorTracer(os.Stderr)

	defer err2.Catch(func(err error) {
		fmt.Println("ERR:", err)
	})

	//try.To(CopyFile("main.go", "main.bak2"))
	try.To(CopyFile("main.go", "/notfound/path/file.bak"))
}

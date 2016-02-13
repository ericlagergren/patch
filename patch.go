package patch

import (
	"errors"
	"log"
	"os"
	"reflect"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/EricLagergren/proc"
)

// Patch is used to modify functions at runtime.
type Patch struct {
	m      proc.Map       // Region we're writing to.
	jmp    [12]byte       // Buffer for our MOVABS + JMP code.
	old    [12]byte       // Code from last patch.
	fnAddr unsafe.Pointer // Address of first func we're patching.
	obj    []byte         // shared object file.
}

// NewPatch patches the fn using the provided .so file.
// soFile must be the path to a .so file and addr must be the index of the
// byte in the file where the function you want to patch with starts.
// fn *must* be a function, *not* a method.
func NewPatch(fn interface{}, soFile string, addr int) (*Patch, error) {

	val := reflect.ValueOf(fn)
	if val.Type().Kind() != reflect.Func {
		return nil, errors.New("fn must be a function")
	}

	// Address of function we want to hot patch.
	fnAddr := val.Pointer()

	m, ok := proc.Find(fnAddr)
	if !ok {
		return nil, errors.New("could not find proper mmapped region")
	}

	buf := mmap(soFile)

	// MOVABSQ $addr, %ra
	b := [12]byte{0x48, 0xb8}

	// Endian-specific 64-bit address.
	*(*uintptr)(unsafe.Pointer(&b[2])) =
		uintptr(unsafe.Pointer(&buf[addr]))

	// JMPQ *%rax
	b[10] = 0xff
	b[11] = 0xe0

	p := &Patch{
		jmp: b,
		m:   m,
		// fnAddr should never go away because it's
		// a function and the GC shouldn't collect
		// functions :-)
		fnAddr: unsafe.Pointer(fnAddr),
		obj:    buf,
	}
	runtime.SetFinalizer(p, (*Patch).Close)
	return p, nil
}

// Patch patches the function and returns any errors that occur.
func (p *Patch) Patch() error {
	// Change the protections so we can write without segfaulting.
	err := p.m.Mprotect(unix.PROT_EXEC | unix.PROT_WRITE | unix.PROT_READ)
	if err != nil {
		return err
	}

	// Reset the protections on the mapping.
	defer p.m.Mprotect(p.m.Perms)

	old := (*[12]byte)(p.fnAddr)

	// Swap out the 12 bytes at the beginning of
	// addr with our hand-crafted MOVABS and JMPQ.
	p.old, *old = *old, p.jmp
	return nil
}

// Unatch undos the previous patch and returns any errors that occur.
func (p *Patch) Unpatch() error {
	err := p.m.Mprotect(unix.PROT_EXEC | unix.PROT_WRITE | unix.PROT_READ)
	if err != nil {
		return err
	}
	defer p.m.Mprotect(p.m.Perms)
	old := (*[12]byte)(p.fnAddr)
	p.jmp, *old = *old, p.old
	return nil
}

// Close releases the shared object file and invalidates the patch.
func (p *Patch) Close() error {
	return unix.Munmap(p.obj)
}

func mmap(name string) []byte {
	file, err := os.Open(name)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		log.Fatalln(err)
	}
	buf, err := unix.Mmap(int(file.Fd()), 0, int(stat.Size()), unix.PROT_EXEC|unix.PROT_WRITE|unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		log.Fatalln(err)
	}
	return buf
}

package main

import (
	"fmt"
	"log"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type patch struct {
	pid  int      // pid of process we want to patch
	addr uintptr  // address of symbol to replace
	jmp  [12]byte // MOVABS + JMP code
	old  [12]byte // code from last patch
	obj  []byte   // mmaped, executable .so file
}

func newPatch(old, new uintptr, pid int, obj []byte) *patch {

	// MOVABSQ $addr, *%rax
	b := [12]byte{0x48, 0xb8}

	// Endian-specific 64-bit address.
	*(*uintptr)(unsafe.Pointer(&b[2])) = new

	// JMPQ *%rax
	b[10] = 0xff
	b[11] = 0xe0

	return &patch{
		pid:  pid,
		addr: old,
		jmp:  b,
		obj:  obj,
	}
}

func (p *patch) wait() error {
	var ws unix.WaitStatus
	_, err := unix.Wait4(p.pid, &ws, 0, nil)
	fmt.Println("ws", ws)
	fmt.Println(ws.Stopped())
	return err
}

func (p *patch) attach() error {
	if err := unix.PtraceAttach(p.pid); err != nil {
		return err
	}
	return p.wait()
}

func (p *patch) detach() error {
	return unix.PtraceDetach(p.pid)
}

func (p *patch) patch() error {
	_, err := unix.PtracePeekData(p.pid, p.addr, p.old[:])
	if err != nil {
		return err
	}
	_, err = unix.PtracePokeData(p.pid, p.addr, p.jmp[:])
	return err
}

// take a file, save the current position, rewind to the beginning,
// mmap the entire thing, then reset the position.
func mmap(file *os.File) []byte {
	cur, err := file.Seek(0, os.SEEK_CUR)
	if err != nil {
		log.Fatalln(err)
	}
	if _, err := file.Seek(0, os.SEEK_SET); err != nil {
		log.Fatalln(err)
	}
	stat, err := file.Stat()
	if err != nil {
		log.Fatalln(err)
	}
	buf, err := unix.Mmap(int(file.Fd()), 0, int(stat.Size()), unix.PROT_EXEC|unix.PROT_WRITE|unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = file.Seek(cur, os.SEEK_SET)
	if err != nil {
		log.Fatalln(err)
	}
	return buf
}

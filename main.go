package main

import (
	"debug/elf"
	"debug/gosym"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/EricLagergren/proc"
)

const debug = false

var (
	obj     = flag.String("obj", "", "object file to link against")
	pid     = flag.Int("pid", -1, "pid of process to modify")
	oldSym  = flag.String("old", "", "symbol to replace")
	newSym  = flag.String("new", "", "replacement symbol")
	version = flag.Bool("version", false, "print the version of this program")
)

func main() {
	log.SetFlags(log.Lshortfile)
	flag.Parse()

	if *pid == -1 {
		log.Fatalln("must set pid of process to edit")
	}

	if !path.IsAbs(*obj) {
		gopath := os.Getenv("GOPATH")
		*obj = filepath.Join(gopath, "pkg", "linux_amd64_dynlink", *obj)
	}

	if debug {
		fmt.Println(*pid)
	}

	ps := proc.NewProcess(*pid)

	exePath, err := ps.ExePath()
	if err != nil {
		log.Fatalln(err)
	}

	exe := open(exePath)
	oldAddr, err := findAddr(exe, *oldSym)
	if err != nil {
		log.Fatalln(err)
	}
	if err := exe.Close(); err != nil {
		log.Fatalln(err)
	}

	objFile := open(*obj)
	newAddr, err := findAddr(objFile, *newSym)
	if err != nil {
		log.Fatalln(err)
	}
	defer objFile.Close()

	pc := newPatch(oldAddr, newAddr, *pid, mmap(objFile))
	if err := pc.attach(); err != nil {
		log.Fatalln(err)
	}
	if err := pc.patch(); err != nil {
		log.Fatalln(err)
	}
	if err := pc.detach(); err != nil {
		log.Fatalln(err)
	}
}

func findAddr(r io.ReaderAt, sym string) (uintptr, error) {
	file, err := elf.NewFile(r)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var (
		textStart       uint64
		symtab, pclntab []byte
	)

	if sect := file.Section(".text"); sect != nil {
		textStart = sect.Addr
	}
	if sect := file.Section(".gosymtab"); sect != nil {
		if symtab, err = sect.Data(); err != nil {
			return 0, err
		}
	}
	if sect := file.Section(".gopclntab"); sect != nil {
		if pclntab, err = sect.Data(); err != nil {
			return 0, err
		}
	}

	tab, err := gosym.NewTable(symtab, gosym.NewLineTable(pclntab, textStart))
	if err != nil {
		return 0, err
	}

	fn := tab.LookupFunc(sym)
	if fn == nil {
		return 0, fmt.Errorf("could not find symbol %q", sym)
	}
	return uintptr(fn.Entry), nil
}

func open(path string) *os.File {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln(err)
	}
	return file
}

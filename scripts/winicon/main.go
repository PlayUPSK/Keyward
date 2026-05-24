package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
)

func main() {
	input := flag.String("in", "", "input PNG path")
	output := flag.String("out", "", "output ICO path")
	flag.Parse()
	if *input == "" || *output == "" {
		panic("-in and -out are required")
	}

	file, err := os.Open(*input)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	src, err := png.Decode(file)
	if err != nil {
		panic(err)
	}

	sizes := []int{16, 32, 48, 64, 128, 256}
	images := make([][]byte, 0, len(sizes))
	for _, size := range sizes {
		var buf bytes.Buffer
		if err := png.Encode(&buf, resizeContain(src, size)); err != nil {
			panic(err)
		}
		images = append(images, buf.Bytes())
	}

	var out bytes.Buffer
	must(binary.Write(&out, binary.LittleEndian, uint16(0)))
	must(binary.Write(&out, binary.LittleEndian, uint16(1)))
	must(binary.Write(&out, binary.LittleEndian, uint16(len(images))))

	offset := 6 + len(images)*16
	for idx, data := range images {
		size := sizes[idx]
		dim := byte(size)
		if size >= 256 {
			dim = 0
		}
		out.WriteByte(dim)
		out.WriteByte(dim)
		out.WriteByte(0)
		out.WriteByte(0)
		must(binary.Write(&out, binary.LittleEndian, uint16(1)))
		must(binary.Write(&out, binary.LittleEndian, uint16(32)))
		must(binary.Write(&out, binary.LittleEndian, uint32(len(data))))
		must(binary.Write(&out, binary.LittleEndian, uint32(offset)))
		offset += len(data)
	}
	for _, data := range images {
		out.Write(data)
	}

	if err := os.WriteFile(*output, out.Bytes(), 0o644); err != nil {
		panic(err)
	}
}

func resizeContain(src image.Image, size int) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(dst, dst.Bounds(), image.NewUniform(color.Transparent), image.Point{}, draw.Src)

	bounds := src.Bounds()
	sw := bounds.Dx()
	sh := bounds.Dy()
	scale := float64(size) / float64(sw)
	if hScale := float64(size) / float64(sh); hScale < scale {
		scale = hScale
	}
	tw := max(1, int(float64(sw)*scale))
	th := max(1, int(float64(sh)*scale))
	x0 := (size - tw) / 2
	y0 := (size - th) / 2

	for y := 0; y < th; y++ {
		sy := bounds.Min.Y + y*sh/th
		for x := 0; x < tw; x++ {
			sx := bounds.Min.X + x*sw/tw
			dst.Set(x0+x, y0+y, src.At(sx, sy))
		}
	}
	return dst
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

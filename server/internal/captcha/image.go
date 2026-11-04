// 自绘图形码的唯一实现（docs/后端架构.md §3.11 行 434、§9.2 行 1084-1091）：
// 生成随机 id + 两位数加减法题面，答案经注入的窄存储接口写 al:cap:{id}
// （TTL 300s 由 cache.CaptchaStore 固定，本包不重复定义存储行为）；校验一律
// 委托同一存储接口的一次性 GETDEL 语义，不另写第二条校验路径。
// 出图只用标准库 image/png 与内置 5x7 点阵字形，零新依赖。
package captcha

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/big"
	"strconv"
)

// ExpiresInSeconds 图形码有效期（§5.1 行 841、接口文档 §2.5 行 494）。
// 实际 TTL 由 cache.CaptchaStore 写键时固定为 300s，本常量仅供响应字段。
const ExpiresInSeconds = 300

// Store 是 image.go 依赖的窄存储接口，cache.CaptchaStore 天然满足：
// Set 写 al:cap:{id}=answer（TTL 由实现方固定 300s）；Verify 为一次性
// GETDEL 比对（正确 / 错误都消费，接口文档 §2.5 行 519）。
type Store interface {
	Set(ctx context.Context, id, answer string) error
	Verify(ctx context.Context, id, answer string) (bool, error)
}

// Challenge 是一次生成的图形码结果。Question 为题面（如 "97-12"），仅供
// 内部测试 / 排查，接口只暴露 ID / image_base64 / expires_in。
type Challenge struct {
	ID        string
	Question  string
	PNG       []byte
	ExpiresIn int
}

// ImageCaptcha 自绘图形码唯一实现。不持有 Redis/DB 句柄，存储行为全部
// 委托注入的 Store（装配层注 cache.CaptchaStore）。
type ImageCaptcha struct {
	store Store
}

// NewImageCaptcha 注入存储实现。
func NewImageCaptcha(store Store) *ImageCaptcha {
	return &ImageCaptcha{store: store}
}

// Generate 生成 id + 题面，先写答案再出图；返回 PNG 字节与 expiresIn=300。
func (c *ImageCaptcha) Generate(ctx context.Context) (Challenge, error) {
	question, answer, err := newQuestion()
	if err != nil {
		return Challenge{}, err
	}
	id, err := newID()
	if err != nil {
		return Challenge{}, err
	}
	if err := c.store.Set(ctx, id, answer); err != nil {
		return Challenge{}, fmt.Errorf("captcha: store image: %w", err)
	}
	raw, err := renderPNG(question)
	if err != nil {
		return Challenge{}, err
	}
	return Challenge{ID: id, Question: question, PNG: raw, ExpiresIn: ExpiresInSeconds}, nil
}

// Verify 委托注入存储做一次性比对（GETDEL 原子消费由 cache 层保证）。
func (c *ImageCaptcha) Verify(ctx context.Context, id, answer string) (bool, error) {
	return c.store.Verify(ctx, id, answer)
}

// newID 生成 16 字节 crypto/rand 的十六进制 id。
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("captcha: random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// randomInt 返回 [min, max) 内的 crypto/rand 整数。
func randomInt(min, max int64) (int64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(max-min))
	if err != nil {
		return 0, fmt.Errorf("captcha: random int: %w", err)
	}
	return n.Int64() + min, nil
}

// newQuestion 生成两位数加减法题面与答案（减法保证结果非负）。
func newQuestion() (question, answer string, err error) {
	left, err := randomInt(10, 100)
	if err != nil {
		return "", "", err
	}
	right, err := randomInt(10, 100)
	if err != nil {
		return "", "", err
	}
	add, err := randomInt(0, 2)
	if err != nil {
		return "", "", err
	}
	if add == 0 {
		return fmt.Sprintf("%d+%d", left, right), strconv.FormatInt(left+right, 10), nil
	}
	if left < right {
		left, right = right, left
	}
	return fmt.Sprintf("%d-%d", left, right), strconv.FormatInt(left-right, 10), nil
}

const (
	glyphCols  = 5
	glyphRows  = 7
	glyphScale = 6
	glyphGap   = 8
	canvasPad  = 18
)

// glyphs 是内置 5x7 点阵字形，覆盖数字与加减法符号；不引入字体文件。
var glyphs = map[byte][glyphRows]string{
	'0': {"01110", "10001", "10001", "10001", "10001", "10001", "01110"},
	'1': {"00100", "01100", "00100", "00100", "00100", "00100", "00100"},
	'2': {"01110", "10001", "00001", "00010", "00100", "01000", "11111"},
	'3': {"01110", "10001", "00001", "00001", "00001", "10001", "01110"},
	'4': {"00001", "00010", "00100", "01000", "11111", "01000", "01000"},
	'5': {"11111", "10000", "10000", "11110", "00001", "00001", "01110"},
	'6': {"00110", "01001", "10001", "10000", "10000", "10001", "01110"},
	'7': {"11111", "00001", "00010", "00100", "01000", "10000", "10000"},
	'8': {"01110", "10001", "10001", "01110", "10001", "10001", "01110"},
	'9': {"01110", "10001", "10001", "01111", "00001", "00001", "01110"},
	'+': {"00000", "00000", "00100", "01110", "00100", "00000", "00000"},
	'-': {"00000", "00000", "00000", "11111", "00000", "00000", "00000"},
	'=': {"00000", "00000", "11111", "00000", "11111", "00000", "00000"},
}

// renderPNG 将题面绘制成 PNG（白底 + 内置点阵 + 噪点 + 干扰线）。
func renderPNG(question string) ([]byte, error) {
	text := question + "="
	width := canvasPad*2 + len(text)*glyphCols*glyphScale + (len(text)-1)*glyphGap
	height := canvasPad*2 + glyphRows*glyphScale

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)

	pool, err := newRandPool(2048)
	if err != nil {
		return nil, err
	}
	drawNoise(img, pool)
	drawLines(img, pool)
	drawText(img, text, pool)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("captcha: encode png: %w", err)
	}
	return buf.Bytes(), nil
}

func drawText(img *image.RGBA, text string, pool *randPool) {
	ink := []color.RGBA{
		{28, 36, 58, 255},
		{58, 32, 30, 255},
		{20, 52, 40, 255},
	}
	for i := 0; i < len(text); i++ {
		glyph, ok := glyphs[text[i]]
		if !ok {
			continue
		}
		x0 := canvasPad + i*(glyphCols*glyphScale+glyphGap)
		y0 := canvasPad + pool.next(5) - 2
		c := ink[pool.next(len(ink))]
		for row := 0; row < glyphRows; row++ {
			for col := 0; col < glyphCols; col++ {
				if glyph[row][col] != '1' {
					continue
				}
				fillRect(img, x0+col*glyphScale, y0+row*glyphScale, glyphScale, glyphScale, c)
			}
		}
	}
}

func drawNoise(img *image.RGBA, pool *randPool) {
	b := img.Bounds()
	c := color.RGBA{170, 178, 198, 255}
	for i := 0; i < b.Dx()*b.Dy()/160; i++ {
		img.SetRGBA(b.Min.X+pool.next(b.Dx()), b.Min.Y+pool.next(b.Dy()), c)
	}
}

func drawLines(img *image.RGBA, pool *randPool) {
	b := img.Bounds()
	c := color.RGBA{130, 150, 190, 255}
	lines := 2 + pool.next(2)
	for i := 0; i < lines; i++ {
		y0 := b.Min.Y + pool.next(b.Dy())
		y1 := b.Min.Y + pool.next(b.Dy())
		for x := b.Min.X; x < b.Max.X; x++ {
			y := y0 + (y1-y0)*(x-b.Min.X)/(b.Dx()-1)
			img.SetRGBA(x, y, c)
			if pool.next(4) == 0 && y+1 < b.Max.Y {
				img.SetRGBA(x, y+1, c)
			}
		}
	}
}

func fillRect(img *image.RGBA, x, y, w, h int, c color.RGBA) {
	b := img.Bounds()
	for yy := y; yy < y+h; yy++ {
		if yy < b.Min.Y || yy >= b.Max.Y {
			continue
		}
		for xx := x; xx < x+w; xx++ {
			if xx < b.Min.X || xx >= b.Max.X {
				continue
			}
			img.SetRGBA(xx, yy, c)
		}
	}
}

// randPool 用一次 crypto/rand 读取的字节池驱动视觉噪声，避免逐像素系统调用。
type randPool struct {
	buf []byte
	idx int
}

func newRandPool(size int) (*randPool, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("captcha: random noise: %w", err)
	}
	return &randPool{buf: buf}, nil
}

func (p *randPool) next(max int) int {
	if max <= 0 {
		return 0
	}
	v := int(p.buf[p.idx])
	p.idx++
	if p.idx == len(p.buf) {
		p.idx = 0
	}
	return v % max
}

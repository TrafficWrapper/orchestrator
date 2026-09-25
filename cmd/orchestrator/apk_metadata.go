package main

import (
	"archive/zip"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"strconv"
	"strings"
	"unicode/utf16"
)

type apkVersionInfo struct {
	VersionCode int64
	VersionName string
	// Package is the manifest package (applicationId) when readable.
	Package string
}

func inspectAPKVersion(file multipart.File, size int64) (apkVersionInfo, error) {
	if size <= 0 {
		return apkVersionInfo{}, errors.New("apk size is empty")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return apkVersionInfo{}, err
	}
	zr, err := zip.NewReader(file, size)
	if err != nil {
		return apkVersionInfo{}, err
	}
	for _, entry := range zr.File {
		if entry.Name != "AndroidManifest.xml" {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return apkVersionInfo{}, err
		}
		raw, readErr := io.ReadAll(io.LimitReader(rc, 8<<20))
		closeErr := rc.Close()
		if readErr != nil {
			return apkVersionInfo{}, readErr
		}
		if closeErr != nil {
			return apkVersionInfo{}, closeErr
		}
		if len(raw) == 8<<20 {
			return apkVersionInfo{}, errors.New("AndroidManifest.xml is too large")
		}
		return parseAPKManifestVersion(raw)
	}
	return apkVersionInfo{}, errors.New("AndroidManifest.xml not found")
}

func parseAPKManifestVersion(raw []byte) (apkVersionInfo, error) {
	if len(raw) > 0 && raw[0] == '<' {
		return parseTextManifestVersion(raw)
	}
	return parseBinaryManifestVersion(raw)
}

func parseTextManifestVersion(raw []byte) (apkVersionInfo, error) {
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return apkVersionInfo{}, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "manifest" {
			continue
		}
		var out apkVersionInfo
		for _, attr := range start.Attr {
			switch attr.Name.Local {
			case "versionCode":
				code, err := strconv.ParseInt(strings.TrimSpace(attr.Value), 10, 64)
				if err != nil {
					return apkVersionInfo{}, err
				}
				out.VersionCode = code
			case "versionName":
				out.VersionName = strings.TrimSpace(attr.Value)
			case "package":
				out.Package = strings.TrimSpace(attr.Value)
			}
		}
		return validateAPKVersionInfo(out)
	}
	return apkVersionInfo{}, errors.New("manifest element not found")
}

// AXML string pool budgets. Strings are decoded lazily, only when a lookup
// needs them, and every decode is charged against the parse so that a
// manifest cannot turn repeated or oversized pool entries into unbounded
// allocations.
const (
	axmlMaxStringCount   = 1 << 18
	axmlMaxStringBytes   = 4 << 10
	axmlMaxDecodedBytes  = 1 << 20
	axmlMaxStringDecodes = 1 << 14
)

var errAXMLBudget = errors.New("AndroidManifest.xml string pool exceeds parse budget")

// axmlBudget is shared by every string pool of one manifest parse.
type axmlBudget struct {
	decodedBytes int
	decodes      int
}

// axmlStringPool indexes a string pool chunk without decoding it.
type axmlStringPool struct {
	chunk        []byte
	headerSize   int
	count        int
	stringsStart int
	utf8         bool
	cache        map[uint32]string
	budget       *axmlBudget
}

func parseBinaryManifestVersion(raw []byte) (apkVersionInfo, error) {
	if len(raw) < 8 || binary.LittleEndian.Uint16(raw[0:2]) != 0x0003 {
		return apkVersionInfo{}, errors.New("unsupported AndroidManifest.xml format")
	}
	pos := int(binary.LittleEndian.Uint16(raw[2:4]))
	if pos <= 0 {
		pos = 8
	}
	budget := &axmlBudget{}
	var pool *axmlStringPool
	for pos+8 <= len(raw) {
		chunkType := binary.LittleEndian.Uint16(raw[pos : pos+2])
		headerSize := int(binary.LittleEndian.Uint16(raw[pos+2 : pos+4]))
		chunkSize := int(binary.LittleEndian.Uint32(raw[pos+4 : pos+8]))
		if headerSize < 8 || chunkSize < headerSize || pos+chunkSize > len(raw) {
			return apkVersionInfo{}, errors.New("invalid AndroidManifest.xml chunk")
		}
		chunk := raw[pos : pos+chunkSize]
		switch chunkType {
		case 0x0001:
			parsed, err := parseAXMLStringPool(chunk, budget)
			if err != nil {
				return apkVersionInfo{}, err
			}
			pool = parsed
		case 0x0102:
			out, ok, err := parseAXMLStartElementVersion(chunk, pool)
			if err != nil {
				return apkVersionInfo{}, err
			}
			if ok {
				return validateAPKVersionInfo(out)
			}
		}
		pos += chunkSize
	}
	return apkVersionInfo{}, errors.New("manifest start element not found")
}

// parseAXMLStringPool validates the pool header and offset table; strings
// are decoded on demand by (*axmlStringPool).get.
func parseAXMLStringPool(chunk []byte, budget *axmlBudget) (*axmlStringPool, error) {
	if len(chunk) < 28 {
		return nil, errors.New("short string pool")
	}
	headerSize := int(binary.LittleEndian.Uint16(chunk[2:4]))
	stringCount := int(binary.LittleEndian.Uint32(chunk[8:12]))
	flags := binary.LittleEndian.Uint32(chunk[16:20])
	stringsStart := int(binary.LittleEndian.Uint32(chunk[20:24]))
	if stringCount > axmlMaxStringCount {
		return nil, errAXMLBudget
	}
	if headerSize < 28 || stringsStart <= 0 || stringsStart > len(chunk) || headerSize+stringCount*4 > len(chunk) {
		return nil, errors.New("invalid string pool")
	}
	return &axmlStringPool{
		chunk:        chunk,
		headerSize:   headerSize,
		count:        stringCount,
		stringsStart: stringsStart,
		utf8:         flags&0x00000100 != 0,
		budget:       budget,
	}, nil
}

// get decodes string idx once and caches it. An absent index (0xffffffff or
// out of range) is the empty string, as before; a malformed or oversized
// string, or an exhausted parse budget, is an error.
func (p *axmlStringPool) get(idx uint32) (string, error) {
	if p == nil || idx == 0xffffffff || uint64(idx) >= uint64(p.count) {
		return "", nil
	}
	if value, ok := p.cache[idx]; ok {
		return value, nil
	}
	if p.budget.decodes >= axmlMaxStringDecodes {
		return "", errAXMLBudget
	}
	p.budget.decodes++
	i := int(idx)
	offset := int(binary.LittleEndian.Uint32(p.chunk[p.headerSize+i*4 : p.headerSize+i*4+4]))
	start := p.stringsStart + offset
	if start < 0 || start >= len(p.chunk) {
		return "", errors.New("invalid string offset")
	}
	var value string
	var err error
	if p.utf8 {
		value, err = decodeAXMLUTF8String(p.chunk[start:])
	} else {
		value, err = decodeAXMLUTF16String(p.chunk[start:])
	}
	if err != nil {
		return "", err
	}
	p.budget.decodedBytes += len(value)
	if p.budget.decodedBytes > axmlMaxDecodedBytes {
		return "", errAXMLBudget
	}
	if p.cache == nil {
		p.cache = make(map[uint32]string)
	}
	p.cache[idx] = value
	return value, nil
}

func parseAXMLStartElementVersion(chunk []byte, pool *axmlStringPool) (apkVersionInfo, bool, error) {
	if len(chunk) < 36 || pool == nil || pool.count == 0 {
		return apkVersionInfo{}, false, nil
	}
	nameIdx := binary.LittleEndian.Uint32(chunk[20:24])
	elementName, err := pool.get(nameIdx)
	if err != nil {
		return apkVersionInfo{}, false, err
	}
	if elementName != "manifest" {
		return apkVersionInfo{}, false, nil
	}
	attrStart := int(binary.LittleEndian.Uint16(chunk[24:26]))
	attrSize := int(binary.LittleEndian.Uint16(chunk[26:28]))
	attrCount := int(binary.LittleEndian.Uint16(chunk[28:30]))
	if attrSize <= 0 {
		attrSize = 20
	}
	base := 16 + attrStart
	var out apkVersionInfo
	for i := 0; i < attrCount; i++ {
		off := base + i*attrSize
		if off+20 > len(chunk) {
			return apkVersionInfo{}, false, errors.New("invalid manifest attribute")
		}
		attrName, err := pool.get(binary.LittleEndian.Uint32(chunk[off+4 : off+8]))
		if err != nil {
			return apkVersionInfo{}, false, err
		}
		rawValueIdx := binary.LittleEndian.Uint32(chunk[off+8 : off+12])
		dataType := chunk[off+15]
		data := binary.LittleEndian.Uint32(chunk[off+16 : off+20])
		switch attrName {
		case "versionCode":
			rawValue, err := pool.get(rawValueIdx)
			if err != nil {
				return apkVersionInfo{}, false, err
			}
			code, err := axmlAttrInt(pool, rawValue, dataType, data)
			if err != nil {
				return apkVersionInfo{}, false, err
			}
			out.VersionCode = code
		case "versionName":
			value, err := axmlAttrString(pool, rawValueIdx, dataType, data)
			if err != nil {
				return apkVersionInfo{}, false, err
			}
			if strings.HasPrefix(value, "@") {
				return apkVersionInfo{}, false, errors.New("versionName is a resource reference; fill it manually")
			}
			out.VersionName = value
		case "package":
			value, err := axmlAttrString(pool, rawValueIdx, dataType, data)
			if err != nil {
				return apkVersionInfo{}, false, err
			}
			out.Package = value
		}
	}
	return out, true, nil
}

func validateAPKVersionInfo(value apkVersionInfo) (apkVersionInfo, error) {
	value.VersionName = strings.TrimSpace(value.VersionName)
	if value.VersionCode <= 0 {
		return apkVersionInfo{}, errors.New("versionCode not found in APK")
	}
	if value.VersionName == "" {
		return apkVersionInfo{}, errors.New("versionName not found in APK")
	}
	return value, nil
}

func axmlAttrInt(pool *axmlStringPool, raw string, dataType byte, data uint32) (int64, error) {
	switch dataType {
	case 0x10, 0x11:
		return int64(data), nil
	case 0x03:
		value, err := pool.get(data)
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(value, 10, 64)
	default:
		if strings.TrimSpace(raw) != "" {
			return strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		}
	}
	return 0, fmt.Errorf("unsupported versionCode type 0x%x", dataType)
}

func axmlAttrString(pool *axmlStringPool, rawIdx uint32, dataType byte, data uint32) (string, error) {
	idx := rawIdx
	if dataType == 0x03 {
		idx = data
	}
	value, err := pool.get(idx)
	return strings.TrimSpace(value), err
}

func decodeAXMLUTF8String(raw []byte) (string, error) {
	_, n1, ok := readAXMLUTF8Length(raw)
	if !ok {
		return "", errors.New("invalid utf8 string length")
	}
	byteLen, n2, ok := readAXMLUTF8Length(raw[n1:])
	if !ok {
		return "", errors.New("invalid utf8 string byte length")
	}
	if byteLen > axmlMaxStringBytes {
		return "", errAXMLBudget
	}
	start := n1 + n2
	end := start + byteLen
	if end > len(raw) {
		return "", errors.New("short utf8 string")
	}
	return string(raw[start:end]), nil
}

func readAXMLUTF8Length(raw []byte) (int, int, bool) {
	if len(raw) == 0 {
		return 0, 0, false
	}
	if raw[0]&0x80 == 0 {
		return int(raw[0]), 1, true
	}
	if len(raw) < 2 {
		return 0, 0, false
	}
	return int(raw[0]&0x7f)<<8 | int(raw[1]), 2, true
}

func decodeAXMLUTF16String(raw []byte) (string, error) {
	length, used, ok := readAXMLUTF16Length(raw)
	if !ok {
		return "", errors.New("invalid utf16 string length")
	}
	if length*2 > axmlMaxStringBytes {
		return "", errAXMLBudget
	}
	start := used
	end := start + length*2
	if end > len(raw) {
		return "", errors.New("short utf16 string")
	}
	words := make([]uint16, length)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(raw[start+i*2 : start+i*2+2])
	}
	return string(utf16.Decode(words)), nil
}

func readAXMLUTF16Length(raw []byte) (int, int, bool) {
	if len(raw) < 2 {
		return 0, 0, false
	}
	first := binary.LittleEndian.Uint16(raw[:2])
	if first&0x8000 == 0 {
		return int(first), 2, true
	}
	if len(raw) < 4 {
		return 0, 0, false
	}
	second := binary.LittleEndian.Uint16(raw[2:4])
	return int(first&0x7fff)<<16 | int(second), 4, true
}

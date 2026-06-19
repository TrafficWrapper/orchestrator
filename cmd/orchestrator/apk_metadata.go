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
			}
		}
		return validateAPKVersionInfo(out)
	}
	return apkVersionInfo{}, errors.New("manifest element not found")
}

func parseBinaryManifestVersion(raw []byte) (apkVersionInfo, error) {
	if len(raw) < 8 || binary.LittleEndian.Uint16(raw[0:2]) != 0x0003 {
		return apkVersionInfo{}, errors.New("unsupported AndroidManifest.xml format")
	}
	pos := int(binary.LittleEndian.Uint16(raw[2:4]))
	if pos <= 0 {
		pos = 8
	}
	var pool []string
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
			parsed, err := parseAXMLStringPool(chunk)
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

func parseAXMLStringPool(chunk []byte) ([]string, error) {
	if len(chunk) < 28 {
		return nil, errors.New("short string pool")
	}
	headerSize := int(binary.LittleEndian.Uint16(chunk[2:4]))
	stringCount := int(binary.LittleEndian.Uint32(chunk[8:12]))
	flags := binary.LittleEndian.Uint32(chunk[16:20])
	stringsStart := int(binary.LittleEndian.Uint32(chunk[20:24]))
	if headerSize < 28 || stringsStart <= 0 || stringsStart > len(chunk) || headerSize+stringCount*4 > len(chunk) {
		return nil, errors.New("invalid string pool")
	}
	utf8Pool := flags&0x00000100 != 0
	out := make([]string, stringCount)
	for i := 0; i < stringCount; i++ {
		offset := int(binary.LittleEndian.Uint32(chunk[headerSize+i*4 : headerSize+i*4+4]))
		start := stringsStart + offset
		if start < 0 || start >= len(chunk) {
			return nil, errors.New("invalid string offset")
		}
		var value string
		var err error
		if utf8Pool {
			value, err = decodeAXMLUTF8String(chunk[start:])
		} else {
			value, err = decodeAXMLUTF16String(chunk[start:])
		}
		if err != nil {
			return nil, err
		}
		out[i] = value
	}
	return out, nil
}

func parseAXMLStartElementVersion(chunk []byte, pool []string) (apkVersionInfo, bool, error) {
	if len(chunk) < 36 || len(pool) == 0 {
		return apkVersionInfo{}, false, nil
	}
	nameIdx := binary.LittleEndian.Uint32(chunk[20:24])
	elementName := axmlString(pool, nameIdx)
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
		attrName := axmlString(pool, binary.LittleEndian.Uint32(chunk[off+4:off+8]))
		rawValue := axmlString(pool, binary.LittleEndian.Uint32(chunk[off+8:off+12]))
		dataType := chunk[off+15]
		data := binary.LittleEndian.Uint32(chunk[off+16 : off+20])
		switch attrName {
		case "versionCode":
			code, err := axmlAttrInt(pool, rawValue, dataType, data)
			if err != nil {
				return apkVersionInfo{}, false, err
			}
			out.VersionCode = code
		case "versionName":
			value := axmlAttrString(pool, rawValue, dataType, data)
			if strings.HasPrefix(value, "@") {
				return apkVersionInfo{}, false, errors.New("versionName is a resource reference; fill it manually")
			}
			out.VersionName = value
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

func axmlAttrInt(pool []string, raw string, dataType byte, data uint32) (int64, error) {
	switch dataType {
	case 0x10, 0x11:
		return int64(data), nil
	case 0x03:
		return strconv.ParseInt(axmlString(pool, data), 10, 64)
	default:
		if strings.TrimSpace(raw) != "" {
			return strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		}
	}
	return 0, fmt.Errorf("unsupported versionCode type 0x%x", dataType)
}

func axmlAttrString(pool []string, raw string, dataType byte, data uint32) string {
	if dataType == 0x03 {
		return strings.TrimSpace(axmlString(pool, data))
	}
	return strings.TrimSpace(raw)
}

func axmlString(pool []string, idx uint32) string {
	if idx == 0xffffffff || int(idx) < 0 || int(idx) >= len(pool) {
		return ""
	}
	return pool[idx]
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

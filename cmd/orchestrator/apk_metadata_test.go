package main

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// buildTestAXMLPoolWithAliases builds a UTF-8 string pool holding values
// followed by aliases extra offset entries that all point at the last value.
func buildTestAXMLPoolWithAliases(values []string, aliases int) []byte {
	var data bytes.Buffer
	offsets := make([]uint32, 0, len(values)+aliases)
	for _, value := range values {
		offsets = append(offsets, uint32(data.Len()))
		chars := len([]rune(value))
		if chars > 0x7f {
			data.WriteByte(byte(0x80 | chars>>8))
			data.WriteByte(byte(chars))
		} else {
			data.WriteByte(byte(chars))
		}
		if len(value) > 0x7f {
			data.WriteByte(byte(0x80 | len(value)>>8))
			data.WriteByte(byte(len(value)))
		} else {
			data.WriteByte(byte(len(value)))
		}
		data.WriteString(value)
		data.WriteByte(0)
	}
	last := offsets[len(offsets)-1]
	for i := 0; i < aliases; i++ {
		offsets = append(offsets, last)
	}
	for data.Len()%4 != 0 {
		data.WriteByte(0)
	}
	headerSize := uint32(28)
	stringsStart := headerSize + uint32(len(offsets))*4
	chunkSize := stringsStart + uint32(data.Len())
	var out bytes.Buffer
	writeTestChunkHeader(&out, 0x0001, uint16(headerSize), chunkSize)
	writeTestU32(&out, uint32(len(offsets)))
	writeTestU32(&out, 0)
	writeTestU32(&out, 0x00000100)
	writeTestU32(&out, stringsStart)
	writeTestU32(&out, 0)
	for _, offset := range offsets {
		writeTestU32(&out, offset)
	}
	out.Write(data.Bytes())
	return out.Bytes()
}

// buildTestAXMLManifestFromPool wraps pool and a manifest start element whose
// versionCode is 7 and whose versionName is pool string versionNameIdx.
func buildTestAXMLManifestFromPool(pool []byte, versionNameIdx uint32) []byte {
	const startSize = 36 + 20*2
	var start bytes.Buffer
	writeTestChunkHeader(&start, 0x0102, 36, startSize)
	writeTestU32(&start, 1)
	writeTestU32(&start, ^uint32(0))
	writeTestU32(&start, ^uint32(0))
	writeTestU32(&start, 0)
	writeTestU16(&start, 20)
	writeTestU16(&start, 20)
	writeTestU16(&start, 2)
	writeTestU16(&start, 0)
	writeTestU16(&start, 0)
	writeTestU16(&start, 0)
	writeTestAXMLAttr(&start, 1, 2, ^uint32(0), 0x10, 7)
	writeTestAXMLAttr(&start, 1, 3, versionNameIdx, 0x03, versionNameIdx)
	var out bytes.Buffer
	writeTestChunkHeader(&out, 0x0003, 8, uint32(8+len(pool)+start.Len()))
	out.Write(pool)
	out.Write(start.Bytes())
	return out.Bytes()
}

func totalAllocDuring(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// ORC-L30: a pool whose many offsets alias one large string must not be
// decoded entry by entry.
func TestAXMLHugeDeclaredStringPoolIsDecodedLazily(t *testing.T) {
	big := strings.Repeat("x", 30000)
	values := []string{"manifest", "http://schemas.android.com/apk/res/android", "versionCode", "versionName", "1.2.3", big}
	pool := buildTestAXMLPoolWithAliases(values, 20000)
	raw := buildTestAXMLManifestFromPool(pool, 4)
	if len(raw) > 8<<20 {
		t.Fatalf("test manifest %d bytes exceeds the upload read limit", len(raw))
	}
	var info apkVersionInfo
	var err error
	allocated := totalAllocDuring(func() {
		info, err = parseAPKManifestVersion(raw)
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if info.VersionCode != 7 || info.VersionName != "1.2.3" {
		t.Fatalf("info=%+v", info)
	}
	if allocated > 8<<20 {
		t.Fatalf("parsing a %d-byte manifest allocated %d bytes", len(raw), allocated)
	}
}

func TestAXMLOversizedStringLookupIsRefused(t *testing.T) {
	big := strings.Repeat("y", axmlMaxStringBytes+1)
	values := []string{"manifest", "http://schemas.android.com/apk/res/android", "versionCode", "versionName", "1.2.3", big}
	raw := buildTestAXMLManifestFromPool(buildTestAXMLPoolWithAliases(values, 0), 5)
	if _, err := parseAPKManifestVersion(raw); !errors.Is(err, errAXMLBudget) {
		t.Fatalf("oversized versionName err=%v want budget error", err)
	}
}

func TestAXMLDeclaredStringCountOverBudgetIsRefused(t *testing.T) {
	pool := buildTestAXMLPoolWithAliases([]string{"manifest"}, 0)
	// Declare far more strings than the chunk can hold.
	pool[8], pool[9], pool[10], pool[11] = 0xff, 0xff, 0xff, 0x7f
	raw := buildTestAXMLManifestFromPool(pool, 0)
	if _, err := parseAPKManifestVersion(raw); err == nil {
		t.Fatal("a pool declaring 2^31 strings was accepted")
	}
}

func TestAXMLDecodeBudgetIsSharedAcrossLookups(t *testing.T) {
	budget := &axmlBudget{}
	values := make([]string, 0, axmlMaxStringDecodes+1)
	for i := 0; i <= axmlMaxStringDecodes; i++ {
		values = append(values, "s")
	}
	pool, err := parseAXMLStringPool(buildTestAXMLPoolWithAliases(values, 0), budget)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < axmlMaxStringDecodes; i++ {
		if _, err := pool.get(uint32(i)); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	if _, err := pool.get(0); err != nil {
		t.Fatalf("cached lookup charged against the budget: %v", err)
	}
	if _, err := pool.get(uint32(axmlMaxStringDecodes)); !errors.Is(err, errAXMLBudget) {
		t.Fatalf("lookup past the decode budget err=%v", err)
	}
}

func FuzzParseAPKManifestVersion(f *testing.F) {
	f.Add(buildTestBinaryManifest(f, 131, "0.1.31"))
	f.Add(buildTestAXMLManifestFromPool(buildTestAXMLPoolWithAliases([]string{"manifest", "ns", "versionCode", "versionName", "1.0"}, 8), 4))
	f.Add([]byte(`<manifest package="a.b" versionCode="3" versionName="1.0"/>`))
	f.Add([]byte{0x03, 0x00, 0x08, 0x00})
	f.Fuzz(func(t *testing.T, raw []byte) {
		info, err := parseAPKManifestVersion(raw)
		if err == nil && (info.VersionCode <= 0 || strings.TrimSpace(info.VersionName) == "") {
			t.Fatalf("accepted manifest without version: %+v", info)
		}
	})
}

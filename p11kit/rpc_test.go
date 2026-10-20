// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package p11kit

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestBuffer(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		do   func(b *buffer) []interface{}
		want []interface{}
	}{
		{
			"uint32",
			[]byte{0x00, 0x00, 0x12, 0x34},
			func(b *buffer) []interface{} {
				var n uint32
				if b.uint32(&n) {
					return []interface{}{n}
				}
				return nil
			},
			[]interface{}{uint32(0x1234)},
		},
		{
			"uint32Twice",
			[]byte{0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x56, 0x78},
			func(b *buffer) []interface{} {
				var n1, n2 uint32
				if b.uint32(&n1) && b.uint32(&n2) {
					return []interface{}{n1, n2}
				}
				return nil
			},
			[]interface{}{uint32(0x1234), uint32(0x5678)},
		},
		{
			"uint64",
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34},
			func(b *buffer) []interface{} {
				var n uint64
				if b.uint64(&n) {
					return []interface{}{n}
				}
				return nil
			},
			[]interface{}{uint64(0x1234)},
		},
		{
			"byteArray",
			[]byte{0x00, 0x00, 0x00, 0x02, 0x12, 0x34},
			func(b *buffer) []interface{} {
				var a []byte
				if b.byteArray(&a) {
					return []interface{}{a}
				}
				return nil
			},
			[]interface{}{[]byte{0x12, 0x34}},
		},
		{
			// p11-kit encodes a CK_DATE as a byte array, length prefix included.
			"date",
			[]byte("\x00\x00\x00\x08" + "12341230" + "\x00\x00\x00\x08" + "20210101"),
			func(b *buffer) []interface{} {
				var t1, t2 time.Time
				var empty1, empty2 bool
				if b.date(&t1, &empty1) && b.date(&t2, &empty2) {
					return []interface{}{t1, empty1, t2, empty2}
				}
				return nil
			},
			[]interface{}{
				time.Date(1234, 12, 30, 0, 0, 0, 0, time.UTC), false,
				time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), false,
			},
		},
		{
			// An empty date arrives as a zero-length byte array, or as the NULL
			// marker when the client passed no value.
			"dateEmpty",
			[]byte{
				0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff,
			},
			func(b *buffer) []interface{} {
				var t1, t2 time.Time
				var empty1, empty2 bool
				if b.date(&t1, &empty1) && b.date(&t2, &empty2) {
					return []interface{}{empty1, empty2}
				}
				return nil
			},
			[]interface{}{true, true},
		},
		{
			// The bytes p11-kit sends for CKA_START_DATE in a template.
			"attributeDate",
			append([]byte{
				0x00, 0x00, 0x01, 0x10, // CKA_START_DATE
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x08, // length: sizeof(CK_DATE)
				0x00, 0x00, 0x00, 0x08, // byte array length
			}, []byte("20210101")...),
			func(b *buffer) []interface{} {
				var a attribute
				if b.attribute(&a) {
					return []interface{}{a}
				}
				return nil
			},
			[]interface{}{attribute{
				typ:  attributeStartDate,
				date: ptrTime(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
			}},
		},
		{
			"attributeDateEmpty",
			[]byte{
				0x00, 0x00, 0x01, 0x11, // CKA_END_DATE
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x00, // length
				0xff, 0xff, 0xff, 0xff, // NULL byte array
			},
			func(b *buffer) []interface{} {
				var a attribute
				if b.attribute(&a) {
					return []interface{}{a}
				}
				return nil
			},
			[]interface{}{attribute{typ: attributeEndDate}},
		},
		{
			// p11-kit serializes attribute types it does not know as byte arrays.
			// NSS 3.130 sends 0x624 in C_FindObjectsInit templates.
			"attributeUnknownType",
			[]byte{
				0x00, 0x00, 0x06, 0x24, // type
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x08, // length
				0x00, 0x00, 0x00, 0x08, // byte array length
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			func(b *buffer) []interface{} {
				var a attribute
				if b.attribute(&a) {
					return []interface{}{a}
				}
				return nil
			},
			[]interface{}{attribute{
				typ:   attributeType(0x624),
				bytes: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			}},
		},
		{
			// p11-kit 0.26.x serializes the IBM vendor attributes with
			// explicit value types, not as byte arrays.
			"attributeIBMRestrictableByte",
			[]byte{
				0x80, 0x01, 0x00, 0x01, // CKA_IBM_RESTRICTABLE
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x01, // length
				0x01,
			},
			func(b *buffer) []interface{} {
				var a attribute
				if b.attribute(&a) {
					return []interface{}{a}
				}
				return nil
			},
			[]interface{}{attribute{typ: attributeIBMRestrictable, byte: ptrByte(1)}},
		},
		{
			"attributeIBMKeyTypeUlong",
			[]byte{
				0x80, 0x01, 0x00, 0x05, // CKA_IBM_KEYTYPE
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x08, // length
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
			},
			func(b *buffer) []interface{} {
				var a attribute
				if b.attribute(&a) {
					return []interface{}{a}
				}
				return nil
			},
			[]interface{}{attribute{typ: attributeIBMKeyType, ulong: ptrUint64(3)}},
		},
		{
			// p11-kit encodes a NULL value with length 0 but still writes the
			// value type's placeholder bytes.
			"attributeByteZeroLength",
			[]byte{
				0x00, 0x00, 0x00, 0x01, // CKA_TOKEN
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x00, // length
				0x00,
			},
			func(b *buffer) []interface{} {
				var a attribute
				if b.attribute(&a) {
					return []interface{}{a}
				}
				return nil
			},
			[]interface{}{attribute{typ: attributeToken, byte: ptrByte(0)}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := newBuffer(test.in)
			got := test.do(&b)
			if len(b.bytes()) != 0 {
				t.Errorf("bytes() after read got=%x, expected no bytes", b.bytes())
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("Decoding got=%#v, want=%#v", got, test.want)
			}
		})
	}
}

func ptrByte(b byte) *byte           { return &b }
func ptrUint64(n uint64) *uint64     { return &n }
func ptrTime(t time.Time) *time.Time { return &t }

// TestBufferAttributeRejects covers attribute encodings that must fail to
// decode rather than desynchronize the stream.
func TestBufferAttributeRejects(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{
			// p11-kit serializes CKA_DERIVE_TEMPLATE as an attribute array,
			// which is not supported.
			"attributeArrayDeriveTemplate",
			[]byte{
				0x40, 0x00, 0x02, 0x13, // CKA_DERIVE_TEMPLATE
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x04, // length
				0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			// A ulong that the peer encoded as a byte array (or the reverse)
			// must be rejected at the attribute boundary. p11-kit master
			// encodes CKA_PARAMETER_SET as a ulong; 0.26.x as a byte array.
			"ulongEncodedForByteArrayType",
			[]byte{
				0x00, 0x00, 0x06, 0x1d, // CKA_PARAMETER_SET
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x08, // length
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // ulong, not a byte array
			},
		},
		{
			"ulongLengthMismatch",
			[]byte{
				0x00, 0x00, 0x00, 0x00, // CKA_CLASS
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x04, // length
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
			},
		},
		{
			"byteLengthMismatch",
			[]byte{
				0x00, 0x00, 0x00, 0x01, // CKA_TOKEN
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x02, // length
				0x01, 0x01,
			},
		},
		{
			// A date without the byte array length prefix p11-kit always writes.
			"dateWithoutLengthPrefix",
			append([]byte{
				0x00, 0x00, 0x01, 0x10, // CKA_START_DATE
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x08, // length
			}, []byte("20210101")...),
		},
		{
			// p11-kit only accepts a date of zero or eight characters.
			"dateWrongLength",
			[]byte{
				0x00, 0x00, 0x01, 0x10, // CKA_START_DATE
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x04, // length
				0x00, 0x00, 0x00, 0x04, // byte array length
				0x32, 0x30, 0x32, 0x31,
			},
		},
		{
			"byteArrayLengthMismatch",
			[]byte{
				0x00, 0x00, 0x00, 0x03, // CKA_LABEL
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x04, // length
				0x00, 0x00, 0x00, 0x02, // byte array length
				0x12, 0x34, 0x56, 0x78,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := newBuffer(test.in)
			var a attribute
			if b.attribute(&a) {
				t.Errorf("attribute() decoded %#v, expected failure", a)
			}
		})
	}
}

func TestBufferAdd(t *testing.T) {
	tests := []struct {
		name string
		do   func(b *buffer)
		want []byte
	}{
		{
			"addUint32",
			func(b *buffer) {
				b.addUint32(0x1234)
			},
			[]byte{0x00, 0x00, 0x12, 0x34},
		},
		{
			"addUint32Twice",
			func(b *buffer) {
				b.addUint32(0x1234)
				b.addUint32(0x5678)
			},
			[]byte{0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x56, 0x78},
		},
		{
			"addUint64",
			func(b *buffer) {
				b.addUint64(0x1234)
			},
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34},
		},
		{
			"addByteArray",
			func(b *buffer) {
				b.addByteArray([]byte{0x12, 0x34})
			},
			[]byte{0x00, 0x00, 0x00, 0x02, 0x12, 0x34},
		},
		{
			"addDate",
			func(b *buffer) {
				t := time.Date(1234, 12, 30, 0, 0, 0, 0, time.UTC)
				b.addDate(t)
				t = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
				b.addDate(t)
			},
			[]byte("\x00\x00\x00\x08" + "12341230" + "\x00\x00\x00\x08" + "20210101"),
		},
		{
			"addAttributeByte",
			func(b *buffer) {
				b.addAttribute(attribute{
					typ:  attributeToken,
					byte: bTrue,
				})
			},
			[]byte{
				0x00, 0x00, 0x00, 0x01,
				0x01,
				0x00, 0x00, 0x00, 0x01,
				0x01,
			},
		},
		{
			"addAttributeULong",
			func(b *buffer) {
				objectClass := ckoCertificate
				b.addAttribute(attribute{
					typ:   attributeClass,
					ulong: &objectClass,
				})
			},
			[]byte{
				0x00, 0x00, 0x00, 0x00,
				0x01,
				0x00, 0x00, 0x00, 0x08,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
		},
		{
			"addAttributeByteArray",
			func(b *buffer) {
				b.addAttribute(attribute{
					typ:   attributeID,
					bytes: []byte{0x12, 0x34, 0x56, 0x78},
				})
			},
			[]byte{
				0x00, 0x00, 0x01, 0x02,
				0x01,
				0x00, 0x00, 0x00, 0x04,
				0x00, 0x00, 0x00, 0x04,
				0x12, 0x34, 0x56, 0x78,
			},
		},
		{
			"addAttributeDate",
			func(b *buffer) {
				t := time.Date(1234, 12, 30, 0, 0, 0, 0, time.UTC)
				b.addAttribute(attribute{
					typ:  attributeStartDate,
					date: &t,
				})
			},
			[]byte{
				0x00, 0x00, 0x01, 0x10, // CKA_START_DATE
				0x01,                   // validity
				0x00, 0x00, 0x00, 0x08, // length: sizeof(CK_DATE)
				0x00, 0x00, 0x00, 0x08, // byte array length
				0x31, 0x32, 0x33, 0x34, 0x31, 0x32, 0x33, 0x30,
			},
		},
		{
			"addAttributeEmpty",
			func(b *buffer) {
				b.addAttribute(attribute{
					typ: attributeWrapTemplate,
				})
			},
			[]byte{
				0x40, 0x00, 0x02, 0x11,
				0x00,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &buffer{}
			test.do(b)
			got := b.bytes()
			if !bytes.Equal(got, test.want) {
				t.Errorf("bytes() got=%x, want=%x", got, test.want)
			}
		})
	}
}

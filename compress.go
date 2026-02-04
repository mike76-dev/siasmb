package main

import (
	"encoding/binary"
	"errors"
	"slices"

	"github.com/mike76-dev/siasmb/compress"
	"github.com/mike76-dev/siasmb/smb2"
)

var errDecompressionError = errors.New("decompression failed")

// decompress decompresses the received message.
func (c *connection) decompress(msg []byte) ([]byte, error) {
	if !c.server.compressionSupported || len(c.compressionIDs) == 0 {
		return nil, smb2.ErrCompressedMessage
	}

	if len(msg) < smb2.SMB2CompressionTransformHeaderSize {
		return nil, smb2.ErrWrongLength
	}

	ocss := smb2.Header(msg).OriginalCompressedSegmentSize()

	if uint64(ocss) > 256+smb2.SMB2CompressionTransformHeaderSize+max(c.maxReadSize, c.maxWriteSize, c.maxTransactSize) {
		return nil, smb2.ErrInvalidParameter
	}

	var output []byte
	chained := c.supportsChainedCompression && smb2.Header(msg).CompressionFlags() == smb2.COMPRESSION_CAPABILITIES_FLAG_CHAINED
	if chained {
		offset := smb2.SMB2CompressionPayloadHeaderOffset
		for {
			if offset == len(msg) {
				break
			}

			if offset+smb2.SMB2CompressionPayloadHeaderSize > len(msg) {
				return nil, smb2.ErrWrongFormat
			}

			ph := smb2.PayloadHeader(msg[offset:])
			algo := ph.CompressionAlgorithm()
			if algo != smb2.COMPRESSION_NONE && !slices.Contains(c.compressionIDs, algo) {
				return nil, smb2.ErrInvalidParameter
			}

			length := ph.Length()
			if offset+smb2.SMB2CompressionPayloadHeaderSize+int(length) > len(msg) {
				return nil, smb2.ErrInvalidParameter
			}

			switch algo {
			case smb2.COMPRESSION_NONE:
				if int(length) > len(msg)-(offset+smb2.SMB2CompressionPayloadHeaderSize) || length > ocss {
					return nil, smb2.ErrInvalidParameter
				}
				output = append(output, msg[offset+smb2.SMB2CompressionPayloadHeaderSize:offset+smb2.SMB2CompressionPayloadHeaderSize+int(length)]...)

			case smb2.COMPRESSION_PATTERN_V1:
				var v1 smb2.PatternV1
				if err := v1.Unmarshal(ph[smb2.SMB2CompressionPayloadHeaderSize:]); err != nil {
					return nil, err
				}
				if v1.Repetitions > ocss {
					return nil, smb2.ErrInvalidParameter
				}
				chunk := make([]byte, v1.Repetitions)
				for i := range v1.Repetitions {
					chunk[i] = v1.Pattern
				}
				output = append(output, chunk...)

			default:
				compressor := compress.New(algo)
				ops := binary.LittleEndian.Uint32(ph[smb2.SMB2CompressionPayloadHeaderSize : smb2.SMB2CompressionPayloadHeaderSize+4])
				chunk, err := compressor.Decompress(ph[smb2.SMB2CompressionPayloadHeaderSize+4:smb2.SMB2CompressionPayloadHeaderSize+length], int(ocss))
				if err != nil {
					return nil, err
				}
				if uint32(len(chunk)) != ops {
					return nil, smb2.ErrWrongLength
				}
				output = append(output, chunk...)
			}

			offset += smb2.SMB2CompressionPayloadHeaderSize + int(length)
		}
	} else {
		offset := smb2.Header(msg).Offset()
		if offset > uint32(len(msg)) {
			return nil, smb2.ErrInvalidParameter
		}

		algo := smb2.Header(msg).CompressionAlgorithm()
		if !slices.Contains(c.compressionIDs, algo) {
			return nil, smb2.ErrInvalidParameter
		}

		switch algo {
		case smb2.COMPRESSION_PATTERN_V1:
			var v1 smb2.PatternV1
			if err := v1.Unmarshal(msg[smb2.SMB2CompressionTransformHeaderSize+offset:]); err != nil {
				return nil, err
			}
			output = make([]byte, v1.Repetitions)
			for i := range v1.Repetitions {
				output[i] = v1.Pattern
			}

		default:
			compressor := compress.New(algo)
			var err error
			output, err = compressor.Decompress(msg[smb2.SMB2CompressionTransformHeaderSize+offset:], int(ocss))
			if err != nil {
				return nil, err
			}
		}
	}

	if uint32(len(output)) != ocss {
		return nil, smb2.ErrWrongLength
	}

	if smb2.Header(output).ProtocolID() != smb2.PROTOCOL_SMB2 {
		return nil, smb2.ErrWrongProtocol
	}

	return output, nil
}

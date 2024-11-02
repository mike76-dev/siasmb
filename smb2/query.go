package smb2

import (
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/mike76-dev/siasmb/utils"
	"go.sia.tech/renterd/api"
)

const (
	SMB2QueryDirectoryRequestMinSize       = 32
	SMB2QueryDirectoryRequestStructureSize = 33

	SMB2QueryDirectoryResponseMinSize       = 8
	SMB2QueryDirectoryResponseStructureSize = 9
)

const (
	FILE_DIRECTORY_INFORMATION                  = 0x01
	FILE_FULL_DIRECTORY_INFORMATION             = 0x02
	FILE_ID_FULL_DIRECTORY_INFORMATION          = 0x26
	FILE_BOTH_DIRECTORY_INFORMATION             = 0x03
	FILE_ID_BOTH_DIRECTORY_INFORMATION          = 0x25
	FILE_NAMES_INFORMATION                      = 0x0c
	FILE_ID_EXTD_DIRECTORY_INFORMATION          = 0x3c
	FILE_ID_64_EXTD_DIRECTORY_INFORMATION       = 0x4e
	FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION  = 0x4f
	FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION      = 0x50
	FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION = 0x51
	FILE_INFORMATION_CLASS_RESERVED             = 0x64
)

const (
	RESTART_SCANS       = 0x01
	RETURN_SINGLE_ENTRY = 0x02
	INDEX_SPECIFIED     = 0x04
	REOPEN              = 0x10
)

type QueryDirectoryRequest struct {
	Request
}

func (qdr QueryDirectoryRequest) Validate() error {
	if err := Header(qdr.data).Validate(); err != nil {
		return err
	}

	if len(qdr.data) < SMB2HeaderSize+SMB2QueryDirectoryRequestMinSize {
		return ErrWrongLength
	}

	if qdr.structureSize() != SMB2QueryDirectoryRequestStructureSize {
		return ErrWrongFormat
	}

	off := binary.LittleEndian.Uint16(qdr.data[SMB2HeaderSize+24 : SMB2HeaderSize+26])
	length := binary.LittleEndian.Uint16(qdr.data[SMB2HeaderSize+26 : SMB2HeaderSize+28])
	if off+length > uint16(len(qdr.data)) {
		return ErrInvalidParameter
	}

	return nil
}

func (qdr QueryDirectoryRequest) FileInformationClass() uint8 {
	return qdr.data[SMB2HeaderSize+2]
}

func (qdr QueryDirectoryRequest) Flags() uint8 {
	return qdr.data[SMB2HeaderSize+3]
}

func (qdr QueryDirectoryRequest) FileIndex() uint32 {
	return binary.LittleEndian.Uint32(qdr.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
}

func (qdr QueryDirectoryRequest) FileID() []byte {
	fid := make([]byte, 16)
	copy(fid, qdr.data[SMB2HeaderSize+8:SMB2HeaderSize+24])
	return fid
}

func (qdr QueryDirectoryRequest) OutputBufferLength() uint32 {
	return binary.LittleEndian.Uint32(qdr.data[SMB2HeaderSize+28 : SMB2HeaderSize+32])
}

func (qdr QueryDirectoryRequest) FileName() string {
	off := binary.LittleEndian.Uint16(qdr.data[SMB2HeaderSize+24 : SMB2HeaderSize+26])
	length := binary.LittleEndian.Uint16(qdr.data[SMB2HeaderSize+26 : SMB2HeaderSize+28])
	return utils.DecodeToString(qdr.data[off : off+length])
}

type dirInfo struct {
	FileIndex      uint32
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
	EndOfFile      uint64
	AllocationSize uint64
	FileAttributes uint32
	EaSize         uint32
	ShortName      string
	FileID         uint64
	FileName       string
}

type fileIDBothDirInfo []dirInfo

func (info fileIDBothDirInfo) encode() []byte {
	var buf []byte
	for i, entry := range info {
		short := utils.EncodeStringToBytes(entry.ShortName)
		long := utils.EncodeStringToBytes(entry.FileName)
		length := 104 + len(long)
		if i < len(info)-1 {
			length = utils.Roundup(length, 8)
		}

		di := make([]byte, length)
		if i < len(info)-1 {
			binary.LittleEndian.PutUint32(di[:4], uint32(length))
		}

		binary.LittleEndian.PutUint32(di[4:8], entry.FileIndex)
		binary.LittleEndian.PutUint64(di[8:16], utils.UnixToFiletime(entry.CreationTime))
		binary.LittleEndian.PutUint64(di[16:24], utils.UnixToFiletime(entry.LastAccessTime))
		binary.LittleEndian.PutUint64(di[24:32], utils.UnixToFiletime(entry.LastWriteTime))
		binary.LittleEndian.PutUint64(di[32:40], utils.UnixToFiletime(entry.ChangeTime))
		binary.LittleEndian.PutUint64(di[40:48], entry.EndOfFile)
		binary.LittleEndian.PutUint64(di[48:56], entry.AllocationSize)
		binary.LittleEndian.PutUint32(di[56:60], entry.FileAttributes)
		binary.LittleEndian.PutUint32(di[64:68], entry.EaSize)
		binary.LittleEndian.PutUint64(di[96:104], entry.FileID)

		di[68] = uint8(len(short))
		copy(di[70:94], short)
		binary.LittleEndian.PutUint32(di[60:64], uint32(len(long)))
		copy(di[104:104+len(long)], long)

		buf = append(buf, di...)
	}

	return buf
}

func QueryDirectoryBuffer(entries []api.ObjectMetadata, bufSize uint32, single, root bool, id, parentID uint64, createdAt, parentCreatedAt time.Time) (buf []byte, num int) {
	var info fileIDBothDirInfo
	size := uint32(224)
	if bufSize < size {
		return nil, 0
	}

	if root {
		info = append(info,
			dirInfo{
				CreationTime:   createdAt,
				LastAccessTime: createdAt,
				LastWriteTime:  createdAt,
				ChangeTime:     createdAt,
				FileAttributes: FILE_ATTRIBUTE_DIRECTORY,
				FileID:         id,
				FileName:       ".",
			},
			dirInfo{
				CreationTime:   parentCreatedAt,
				LastAccessTime: parentCreatedAt,
				LastWriteTime:  parentCreatedAt,
				ChangeTime:     parentCreatedAt,
				FileAttributes: FILE_ATTRIBUTE_DIRECTORY,
				FileID:         parentID,
				FileName:       "..",
			},
		)
	}

	for i, entry := range entries {
		_, name, isDir := utils.ExtractFilename(entry.Name)
		length := 104 + uint32(len(name))*2
		if size+length > bufSize {
			break
		}

		di := dirInfo{
			CreationTime:   time.Time(entry.ModTime),
			LastAccessTime: time.Time(entry.ModTime),
			LastWriteTime:  time.Time(entry.ModTime),
			ChangeTime:     time.Time(entry.ModTime),
			FileName:       name,
		}

		if isDir {
			di.FileAttributes = FILE_ATTRIBUTE_DIRECTORY
		} else {
			di.FileAttributes = FILE_ATTRIBUTE_NORMAL
			di.EndOfFile = uint64(entry.Size)
			di.AllocationSize = (uint64(entry.Size) + (clusterSize - 1)) &^ (clusterSize - 1)
		}

		fid, _ := hex.DecodeString(entry.ETag)
		if len(fid) >= 8 {
			di.FileID = binary.LittleEndian.Uint64(fid[:8])
		}

		info = append(info, di)
		num++
		if !single && i < len(entries)-1 && size+uint32(utils.Roundup(104+len(name)*2, 8)) <= bufSize {
			size += uint32(utils.Roundup(104+len(name)*2, 8))
		} else {
			break
		}
	}

	return info.encode(), num
}

type QueryDirectoryResponse struct {
	Response
}

func (qdr *QueryDirectoryResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(qdr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2QueryDirectoryResponseStructureSize)
}

func (qdr *QueryDirectoryResponse) SetOutputBuffer(buf []byte) {
	binary.LittleEndian.PutUint16(qdr.data[SMB2HeaderSize+2:SMB2HeaderSize+4], uint16(len(qdr.data)))
	binary.LittleEndian.PutUint32(qdr.data[SMB2HeaderSize+4:SMB2HeaderSize+8], uint32(len(buf)))
	qdr.data = append(qdr.data, buf...)
}

func (qdr *QueryDirectoryResponse) FromRequest(req GenericRequest) {
	qdr.Response.FromRequest(req)

	body := make([]byte, SMB2QueryDirectoryResponseMinSize)
	qdr.data = append(qdr.data, body...)

	qdr.setStructureSize()
	Header(qdr.data).SetNextCommand(0)
	Header(qdr.data).SetStatus(STATUS_OK)
	if Header(qdr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(qdr.data).SetCreditResponse(0)
	} else {
		Header(qdr.data).SetCreditResponse(1)
	}
}

func (qdr *QueryDirectoryResponse) Generate(buf []byte) {
	qdr.SetOutputBuffer(buf)
}

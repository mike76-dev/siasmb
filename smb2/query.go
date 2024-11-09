package smb2

import (
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/mike76-dev/siasmb/utils"
	"go.sia.tech/renterd/api"
	"golang.org/x/crypto/blake2b"
)

const (
	SMB2QueryDirectoryRequestMinSize       = 32
	SMB2QueryDirectoryRequestStructureSize = 33

	SMB2QueryDirectoryResponseMinSize       = 8
	SMB2QueryDirectoryResponseStructureSize = 9

	SMB2QueryInfoRequestMinSize       = 40
	SMB2QueryInfoRequestStructureSize = 41

	SMB2QueryInfoResponseMinSize       = 8
	SMB2QueryInfoResponseStructureSize = 9
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

const (
	INFO_FILE       = 0x01
	INFO_FILESYSTEM = 0x02
	INFO_SECURITY   = 0x03
	INFO_QUOTA      = 0x04
)

const (
	FileAccessInformation         = 0x08
	FileAlignmentInformation      = 0x11
	FileAllInformation            = 0x12
	FileAlternateNameInformation  = 0x15
	FileAttributeTagInformation   = 0x23
	FileBasicInformation          = 0x04
	FileCompressionInformation    = 0x1c
	FileEaInformation             = 0x07
	FileFullEaInformation         = 0x0f
	FileIdInformation             = 0x3b
	FileInternalInformation       = 0x06
	FileModeInformation           = 0x10
	FileNetworkOpenInformation    = 0x22
	FileNormalizedNameInformation = 0x30
	FilePipeInformation           = 0x17
	FilePipeLocalInformation      = 0x18
	FilePipeRemoteInformation     = 0x19
	FilePositionInformation       = 0x0e
	FileStandardInformation       = 0x05
	FileStreamInformation         = 0x16
	FileInfoClass_Reserved        = 0x64

	FileFsAttributeInformation  = 0x05
	FileFsControlInformation    = 0x06
	FileFsDeviceInformation     = 0x04
	FileFsFullSizeInformation   = 0x07
	FileFsObjectIdInformation   = 0x08
	FileFsSectorSizeInformation = 0x0b
	FileFsSizeInformation       = 0x03
	FileFsVolumeInformation     = 0x01
)

const (
	OWNER_SECURITY_INFORMATION     = 0x00000001
	GROUP_SECURITY_INFORMATION     = 0x00000002
	DACL_SECURITY_INFORMATION      = 0x00000004
	SACL_SECURITY_INFORMATION      = 0x00000008
	LABEL_SECURITY_INFORMATION     = 0x00000010
	ATTRIBUTE_SECURITY_INFORMATION = 0x00000020
	SCOPE_SECURITY_INFORMATION     = 0x00000040
	BACKUP_SECURITY_INFORMATION    = 0x00010000
)

const (
	SL_RESTART_SCAN        = 0x00000001
	SL_RETURN_SINGLE_ENTRY = 0x00000002
	SL_INDEX_SPECIFIED     = 0x00000004
)

const (
	totalSize = 1024 * 1024 * 1024 * 1024
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
			di.AllocationSize = (uint64(entry.Size) + (ClusterSize - 1)) &^ (ClusterSize - 1)
		}

		fid, _ := hex.DecodeString(entry.ETag)
		if len(fid) >= 8 {
			di.FileID = binary.LittleEndian.Uint64(fid[:8])
		} else {
			hash := blake2b.Sum256([]byte(entry.Name))
			di.FileID = binary.LittleEndian.Uint64(hash[:8])
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
	}
}

func (qdr *QueryDirectoryResponse) Generate(buf []byte) {
	qdr.SetOutputBuffer(buf)
}

type QueryInfoRequest struct {
	Request
}

func (qir QueryInfoRequest) Validate() error {
	if err := Header(qir.data).Validate(); err != nil {
		return err
	}

	if len(qir.data) < SMB2HeaderSize+SMB2QueryInfoRequestMinSize {
		return ErrWrongLength
	}

	if qir.structureSize() != SMB2QueryInfoRequestStructureSize {
		return ErrWrongFormat
	}

	off := binary.LittleEndian.Uint16(qir.data[SMB2HeaderSize+8 : SMB2HeaderSize+10])
	length := binary.LittleEndian.Uint32(qir.data[SMB2HeaderSize+12 : SMB2HeaderSize+16])
	if uint32(off)+length > uint32(len(qir.data)) {
		return ErrInvalidParameter
	}

	return nil
}

func (qir QueryInfoRequest) InfoType() uint8 {
	return qir.data[SMB2HeaderSize+2]
}

func (qir QueryInfoRequest) FileInfoClass() uint8 {
	return qir.data[SMB2HeaderSize+3]
}

func (qir QueryInfoRequest) OutputBufferLength() uint32 {
	return binary.LittleEndian.Uint32(qir.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
}

func (qir QueryInfoRequest) InputBuffer() []byte {
	off := binary.LittleEndian.Uint16(qir.data[SMB2HeaderSize+8 : SMB2HeaderSize+10])
	length := binary.LittleEndian.Uint32(qir.data[SMB2HeaderSize+12 : SMB2HeaderSize+16])
	return qir.data[off : uint32(off)+length]
}

func (qir QueryInfoRequest) AdditionalInformation() uint32 {
	return binary.LittleEndian.Uint32(qir.data[SMB2HeaderSize+16 : SMB2HeaderSize+20])
}

func (qir QueryInfoRequest) Flags() uint32 {
	return binary.LittleEndian.Uint32(qir.data[SMB2HeaderSize+20 : SMB2HeaderSize+24])
}

func (qir QueryInfoRequest) FileID() []byte {
	fid := make([]byte, 16)
	copy(fid, qir.data[SMB2HeaderSize+24:SMB2HeaderSize+40])
	return fid
}

type QueryInfoResponse struct {
	Response
}

func (qir *QueryInfoResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(qir.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2QueryInfoResponseStructureSize)
}

func (qir *QueryInfoResponse) SetOutputBuffer(buf []byte) {
	binary.LittleEndian.PutUint16(qir.data[SMB2HeaderSize+2:SMB2HeaderSize+4], uint16(len(qir.data)))
	binary.LittleEndian.PutUint32(qir.data[SMB2HeaderSize+4:SMB2HeaderSize+8], uint32(len(buf)))
	qir.data = append(qir.data, buf...)
}

func (qir *QueryInfoResponse) FromRequest(req GenericRequest) {
	qir.Response.FromRequest(req)

	body := make([]byte, SMB2QueryInfoResponseMinSize)
	qir.data = append(qir.data, body...)

	qir.setStructureSize()
	Header(qir.data).SetNextCommand(0)
	Header(qir.data).SetStatus(STATUS_OK)
	if Header(qir.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(qir.data).SetCreditResponse(0)
	}
}

func (qir *QueryInfoResponse) Generate(buf []byte) {
	qir.SetOutputBuffer(buf)
}

func FileFsVolumeInfo(createdAt time.Time, serialNo uint32, label string) []byte {
	vl := utils.EncodeStringToBytes(label)
	if len(vl) > 32 {
		vl = vl[:32]
	}

	info := make([]byte, 18+len(vl))
	binary.LittleEndian.PutUint64(info[:8], utils.UnixToFiletime(createdAt))
	binary.LittleEndian.PutUint32(info[8:12], serialNo)
	binary.LittleEndian.PutUint32(info[12:16], uint32(len(vl)))
	copy(info[18:18+len(vl)], vl)

	return info
}

func FileFsAttributeInfo() []byte {
	name := utils.EncodeStringToBytes("renterd")
	info := make([]byte, 12+len(name))
	binary.LittleEndian.PutUint32(info[:4], 0x01100103)
	binary.LittleEndian.PutUint32(info[4:8], 255)
	binary.LittleEndian.PutUint32(info[8:12], uint32(len(name)))
	copy(info[12:12+len(name)], name)
	return info
}

func FileFsFullSizeInfo(spu int) []byte {
	info := make([]byte, 32)
	units := totalSize / ClusterSize / uint64(spu)
	binary.LittleEndian.PutUint64(info[:8], units)
	binary.LittleEndian.PutUint64(info[8:16], units)
	binary.LittleEndian.PutUint64(info[16:24], units)
	binary.LittleEndian.PutUint32(info[24:28], uint32(spu))
	binary.LittleEndian.PutUint32(info[28:32], uint32(ClusterSize))
	return info
}

type FileBasicInfo struct {
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
	FileAttributes uint32
}

func (fbi FileBasicInfo) Encode() []byte {
	buf := make([]byte, 40)
	binary.LittleEndian.PutUint64(buf[:8], utils.UnixToFiletime(fbi.CreationTime))
	binary.LittleEndian.PutUint64(buf[8:16], utils.UnixToFiletime(fbi.LastAccessTime))
	binary.LittleEndian.PutUint64(buf[16:24], utils.UnixToFiletime(fbi.LastWriteTime))
	binary.LittleEndian.PutUint64(buf[24:32], utils.UnixToFiletime(fbi.ChangeTime))
	binary.LittleEndian.PutUint32(buf[32:36], fbi.FileAttributes)
	return buf
}

type FileStandardInfo struct {
	AllocationSize uint64
	EndOfFile      uint64
	NumberOfLinks  uint32
	DeletePending  bool
	Directory      bool
}

func (fsi FileStandardInfo) Encode() []byte {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint64(buf[:8], fsi.AllocationSize)
	binary.LittleEndian.PutUint64(buf[8:16], fsi.EndOfFile)
	binary.LittleEndian.PutUint32(buf[16:20], fsi.NumberOfLinks)
	if fsi.DeletePending {
		buf[20] = 1
	}
	if fsi.Directory {
		buf[21] = 1
	}
	return buf
}

type FileInternalInfo struct {
	IndexNumber uint64
}

func (fii FileInternalInfo) Encode() []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, fii.IndexNumber)
	return buf
}

type FileEaInfo struct {
	EaSize uint32
}

func (fei FileEaInfo) Encode() []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, fei.EaSize)
	return buf
}

type FileAccessInfo struct {
	AccessFlags uint32
}

func (fai FileAccessInfo) Encode() []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, fai.AccessFlags)
	return buf
}

type FilePositionInfo struct {
	CurrentByteOffset uint64
}

func (fpi FilePositionInfo) Encode() []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, fpi.CurrentByteOffset)
	return buf
}

type FileModeInfo struct {
	Mode uint32
}

func (fmi FileModeInfo) Encode() []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, fmi.Mode)
	return buf
}

type FileAlignmentInfo struct {
	AlignmentRequirement uint32
}

func (fai FileAlignmentInfo) Encode() []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, fai.AlignmentRequirement)
	return buf
}

type FileNameInfo struct {
	FileName string
}

func (fni FileNameInfo) Encode() []byte {
	name := utils.EncodeStringToBytes(fni.FileName)
	buf := make([]byte, len(name)+4)
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(name)))
	copy(buf[4:], name)
	return buf
}

type FileAllInfo struct {
	BasicInfo     FileBasicInfo
	StandardInfo  FileStandardInfo
	InternalInfo  FileInternalInfo
	EaInfo        FileEaInfo
	AccessInfo    FileAccessInfo
	PositionInfo  FilePositionInfo
	ModeInfo      FileModeInfo
	AlignmentInfo FileAlignmentInfo
	NameInfo      FileNameInfo
}

func (fai FileAllInfo) Encode() []byte {
	return append(
		append(
			append(
				append(
					append(
						append(
							append(
								append(
									fai.BasicInfo.Encode(),
									fai.StandardInfo.Encode()...,
								),
								fai.InternalInfo.Encode()...,
							),
							fai.EaInfo.Encode()...,
						),
						fai.AccessInfo.Encode()...,
					),
					fai.PositionInfo.Encode()...,
				),
				fai.ModeInfo.Encode()...,
			),
			fai.AlignmentInfo.Encode()...,
		),
		fai.NameInfo.Encode()...,
	)
}

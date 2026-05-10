package connsec

import (
	"fmt"
	"io"

	"github.com/julinox/funtls/tlssl"
)

func (x *xTLSConn) Read(p []byte) (int, error) {

	if len(p) == 0 {
		return 0, nil
	}

	for {
		if x.readBuf.Len() > 0 {
			break
		}

		if x.peerClose {
			x.Close()
		}

		if x.eofRead {
			return 0, io.EOF
		}

		//tmp := make([]byte, 4096)
		tmp := make([]byte, 1)
		//fmt.Printf("tmp Len=%v | Cap=%v\n", len(tmp), cap(tmp))
		n, err := x.rawConn.Read(tmp)
		fmt.Printf("%v || tmp Len=%v | Cap=%v | n: %v\n", x.cntt, len(tmp), cap(tmp), n)
		x.cntt++
		if err != nil {
			if err == io.EOF {
				x.eofRead = true
			}

			if n <= 0 {
				return 0, err
			}
		}

		x.readRawBuf = append(x.readRawBuf, tmp[:n]...)
		for {
			if len(x.readRawBuf) < tlssl.TLS_HEADER_SIZE {
				break
			}

			pktSz := int(x.readRawBuf[3])<<8 | int(x.readRawBuf[4])
			if pktSz > _MaxTLSRecordSize_ {
				return 0, fmt.Errorf("invalid record size")
			}

			if len(x.readRawBuf) < pktSz+tlssl.TLS_HEADER_SIZE {
				break
			}

			record := x.readRawBuf[:pktSz+tlssl.TLS_HEADER_SIZE]
			if record[0] == byte(tlssl.ContentTypeAlert) {
				x.handleAlert(record)
				break
			}

			auxgg := make([]byte, 0, tlssl.MALLOCBUFF)
			plainText, err := x.specRead.DecryptRec(auxgg, record)
			if err != nil {
				x.lg.Error("Error decrypting TLS record: ", err)
				if !x.debugMode {
					return 0, err
				}

				x.lg.Debugf("RawRead: %x",
					x.readRawBuf[:pktSz+tlssl.TLS_HEADER_SIZE])
			}

			x.readRawBuf = x.readRawBuf[pktSz+tlssl.TLS_HEADER_SIZE:]
			if plainText != nil {
				x.readBuf.Write(plainText)
			}
		}
	}

	return x.readBuf.Read(p)
}

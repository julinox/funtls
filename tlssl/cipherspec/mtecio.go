package cipherspec

type mteEtm struct {
	iv  []byte
	mac []byte
	dst []byte
	src []byte
}

/*
func (x *xCS) encryptMTEAux(data *mteEtm, ct uint8) ([]byte, error) {

	var sCtx suite.SuiteContext

	myself := systema.MyName()
	sCtx.Key = x.keys.Key
	srcBuff := x.srcPoolBuff.Get()
	defer x.srcPoolBuff.Put(srcBuff)

	offset := data.dst[:tlssl.TLS_HEADER_SIZE]
	if x.seqNum == 0 {
		srcBuff = append(srcBuff, data.iv...)
		srcBuff = append(srcBuff, data.src...)
		srcBuff = append(srcBuff, data.mac...)
		sCtx.IV = x.keys.IV
	} else {
		srcBuff = append(srcBuff, data.src...)
		srcBuff = append(srcBuff, data.mac...)
		offset = append(offset, data.iv...)
		sCtx.IV = data.iv
	}

	ciphered, err := x.cipherSuite.Cipher(offset[len(offset):], srcBuff, &sCtx)
	if err != nil {
		return nil, fmt.Errorf("Ciphering(%v): %v", myself, err)
	}

	offset = offset[:len(offset)+len(ciphered)]
	header := tlssl.TLSHeadPacket(&tlssl.TLSHeader{
		ContentType: tlssl.ContentTypeType(ct),
		Version:     tlssl.TLS_VERSION1_2,
		Len:         len(offset) - tlssl.TLS_HEADER_SIZE,
	})

	copy(offset, header)
	return offset, nil
}
*/

/*
func (x *xCS) encryptMTESN0(data *mteEtm, ct uint8) ([]byte, error) {

	var sCtx suite.SuiteContext

	myself := systema.MyName()
	sCtx.IV = x.keys.IV
	sCtx.Key = x.keys.Key
	srcBuff := ftbuffer.GiveMe33(len(data.iv) + len(data.src) + len(data.mac))
	srcBuff = append(srcBuff, data.iv...)
	srcBuff = append(srcBuff, data.src...)
	srcBuff = append(srcBuff, data.mac...)
	offset := data.dst[:tlssl.TLS_HEADER_SIZE]
	ciphered, err := x.cipherSuite.Cipher(offset[len(offset):], srcBuff, &sCtx)
	if err != nil {
		return nil, fmt.Errorf("Ciphering(%v): %v", myself, err)
	}

	offset = offset[:len(offset)+len(ciphered)]
	header := tlssl.TLSHeadPacket(&tlssl.TLSHeader{
		ContentType: tlssl.ContentTypeType(ct),
		Version:     tlssl.TLS_VERSION1_2,
		Len:         len(ciphered),
	})

	copy(offset, header)
	return offset, nil
}

func (x *xCS) encryptMTESNN(data *mteEtm, ct uint8) ([]byte, error) {

	var sCtx suite.SuiteContext

	myself := systema.MyName()
	srcBuff := ftbuffer.GiveMe33(len(data.src) + x.cipherSuite.Info().HashSize)
	srcBuff = append(srcBuff, data.src...)
	srcBuff = append(srcBuff, data.mac...)
	offset := data.dst[:tlssl.TLS_HEADER_SIZE]
	offset = append(offset, data.iv...)
	sCtx.IV = data.iv
	sCtx.Key = x.keys.Key
	ciphered, err := x.cipherSuite.Cipher(offset[len(offset):], srcBuff, &sCtx)
	if err != nil {
		return nil, fmt.Errorf("ciphering(%v): %v", myself, err)
	}

	offset = offset[:len(offset)+len(ciphered)]
	header := tlssl.TLSHeadPacket(&tlssl.TLSHeader{
		ContentType: tlssl.ContentTypeType(ct),
		Version:     tlssl.TLS_VERSION1_2,
		Len:         len(offset) - tlssl.TLS_HEADER_SIZE,
	})

	//fmt.Printf("SrcBuff: %v | Ciphered: %v | OFFSET: %v\n", len(srcBuff), len(ciphered), len(offset))
	copy(offset, header)
	return offset, nil
}
*/

/*
func (x *xCS) encryptMTELast(dst, src []byte, ct uint8) ([]byte, error) {

	var err error
	var srcBuff []byte
	var fragment []byte
	var sCtx suite.SuiteContext

	myself := systema.MyName()
	if len(src) == 0 {
		return nil, fmt.Errorf("empty plaintext (%v)", myself)
	}

	mac, err := x.macintosh(src, ct)
	if err != nil {
		return nil, fmt.Errorf("macOS(%v): %v", myself, err)
	}

	ivSz := x.cipherSuite.Info().IVSize
	iv, err := generateIVNonce(ivSz)
	if err != nil {
		return nil, fmt.Errorf("generateIVNonce(%v): %v", myself, err)
	}

	if x.seqNum == 0 {
		srcBuff = make([]byte, 0, ivSz+len(src)+x.cipherSuite.Info().HashSize)
		sCtx.IV = x.keys.IV
		srcBuff = append(srcBuff, iv...)
	} else {
		srcBuff = make([]byte, 0, len(src)+x.cipherSuite.Info().HashSize)
		sCtx.IV = iv
		fragment = append(fragment, iv...)
		//fmt.Printf("DATA1: %x\n", src)
		//fmt.Printf("MAC1: %x\n", mac)
		//x.encryptMTEGG(dst, src, ct)
	}

	srcBuff = append(srcBuff, src...)
	srcBuff = append(srcBuff, mac...)
	sCtx.Key = x.keys.Key
	ciphered, err := x.cipherSuite.Cipher(dst, srcBuff, &sCtx)
	if err != nil {
		return nil, fmt.Errorf("Ciphering(%v): %v", myself, err)
	}

	fragment = append(fragment, ciphered...)
	header := tlssl.TLSHeadPacket(&tlssl.TLSHeader{
		ContentType: tlssl.ContentTypeType(ct),
		Version:     tlssl.TLS_VERSION1_2,
		Len:         len(fragment),
	})

	return append(header, fragment...), nil
}

func (x *xCS) encryptMTE3(dst, src []byte, ct uint8) ([]byte, error) {

	var err error
	var fragment []byte
	var sCtx suite.SuiteContext

	myself := systema.MyName()
	if len(src) == 0 {
		return nil, fmt.Errorf("empty plaintext (%v)", myself)
	}

	mac, err := x.macintosh(src, ct)
	if err != nil {
		return nil, fmt.Errorf("macOS(%v): %v", myself, err)
	}

	iv, err := generateIVNonce(x.cipherSuite.Info().IVSize)
	if err != nil {
		return nil, fmt.Errorf("generateIVNonce(%v): %v", myself, err)
	}

	if x.seqNum == 0 {
		sCtx.IV = x.keys.IV
		sCtx.Data = append(sCtx.Data, iv...)
	} else {
		sCtx.IV = iv
		fragment = append(fragment, iv...)
	}

	sCtx.Key = x.keys.Key
	sCtx.Data = append(sCtx.Data, src...)
	sCtx.Data = append(sCtx.Data, mac...)
	ciphered, err := x.cipherSuite.Cipher(nil, nil, &sCtx)
	if err != nil {
		return nil, fmt.Errorf("Ciphering(%v): %v", myself, err)
	}

	fragment = append(fragment, ciphered...)
	header := tlssl.TLSHeadPacket(&tlssl.TLSHeader{
		ContentType: tlssl.ContentTypeType(ct),
		Version:     tlssl.TLS_VERSION1_2,
		Len:         len(fragment),
	})

	return append(header, fragment...), nil
}
*/

package analyzer

// extractSNI достаёт имя сервера из TLS ClientHello.
// Работает на уровне байтов, чтобы не тянуть полный парсер TLS.
func extractSNI(payload []byte) (string, bool) {
	// Заголовок TLS record: тип 0x16 (handshake), версия, длина.
	if len(payload) < 5 || payload[0] != 0x16 {
		return "", false
	}
	recLen := int(payload[3])<<8 | int(payload[4])
	end := 5 + recLen
	if end > len(payload) {
		return "", false
	}
	rec := payload[5:end]

	// Заголовок handshake: тип 0x01 (ClientHello), длина 3 байта.
	if len(rec) < 4 || rec[0] != 0x01 {
		return "", false
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	body := rec[4:]
	if hsLen < len(body) {
		body = body[:hsLen]
	}

	q := body
	// version (2) + random (32).
	if len(q) < 34 {
		return "", false
	}
	q = q[34:]

	// session id.
	if len(q) < 1 {
		return "", false
	}
	sidLen := int(q[0])
	q = q[1:]
	if len(q) < sidLen+2 {
		return "", false
	}
	q = q[sidLen:]

	// cipher suites.
	csLen := int(q[0])<<8 | int(q[1])
	q = q[2:]
	if len(q) < csLen+1 {
		return "", false
	}
	q = q[csLen:]

	// compression methods.
	compLen := int(q[0])
	q = q[1:]
	if len(q) < compLen+2 {
		return "", false
	}
	q = q[compLen:]

	// extensions.
	extLen := int(q[0])<<8 | int(q[1])
	q = q[2:]
	if extLen < len(q) {
		q = q[:extLen]
	}

	for len(q) >= 4 {
		extType := int(q[0])<<8 | int(q[1])
		extBody := int(q[2])<<8 | int(q[3])
		q = q[4:]
		if extBody > len(q) {
			return "", false
		}
		data := q[:extBody]
		q = q[extBody:]

		if extType != 0x0000 { // server_name
			continue
		}
		// data: list length (2), entry type (1) = 0, name length (2), name.
		if len(data) < 5 || data[2] != 0x00 {
			return "", false
		}
		nameLen := int(data[3])<<8 | int(data[4])
		if 5+nameLen > len(data) {
			return "", false
		}
		name := string(data[5 : 5+nameLen])
		if name == "" {
			return "", false
		}
		return name, true
	}
	return "", false
}

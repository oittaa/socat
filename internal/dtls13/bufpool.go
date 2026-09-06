package dtls13

const (
	maxRecycledDatagrams = 32
	maxRecycledApp       = 32
)

func takeBuffer(free *[][]byte, n int) []byte {
	for i, buf := range *free {
		if cap(buf) >= n {
			last := len(*free) - 1
			(*free)[i] = (*free)[last]
			(*free)[last] = nil
			*free = (*free)[:last]
			return buf[:n]
		}
	}
	return make([]byte, n)
}

func putBuffer(free *[][]byte, buf []byte, maxN, maxCap int) {
	if buf == nil || cap(buf) == 0 || cap(buf) > maxCap || len(*free) >= maxN {
		return
	}
	*free = append(*free, buf[:0])
}

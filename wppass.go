package wppass

import (
	"crypto/md5"
	"errors"
)

const (
	top    = "$P$B"
	itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

//VerfiyPass 验证wodpress的密码 用户密码,对比密码
func VerfiyPass(passwd, hashPass string) bool {
	if len(hashPass) != 34 || hashPass[0:4] != top {
		return false
	}
	salt := hashPass[4:12]
	if pass, err := HashPass(salt, passwd); err == nil {
		return pass != "" && pass == hashPass
	}
	return false
}

//HashPass 生成wordpress的密码 8位字符串盐,要加密的密码
func HashPass(salt, passwd string) (string, error) {
	if len(salt) != 8 {
		return "", errors.New("salt length not of 8")
	}
	a := salt + passwd
	b := hashMd5(a)
	for i := 1; i <= 8192; i++ {
		a = b + passwd
		b = hashMd5(a)
	}
	var (
		count  int    = 16
		input  string = b
		output string
	)
	for i := 0; i < count; i++ {
		value := int(input[i])
		output = output + itoa64[(value&0x3f):(value&0x3f)+1]
		i++
		if i < count {
			value = int(value) + (int(input[i]) << 8)
		}
		output = output + itoa64[((value>>6)&0x3f):((value>>6)&0x3f)+1]
		if i > count {
			break
		}
		i++
		if i < count {
			value = int(value) + (int(input[i]) << 16)
		}
		output = output + itoa64[((value>>12)&0x3f):((value>>12)&0x3f)+1]
		if i > count {
			break
		}
		output = output + itoa64[((value>>18)&0x3f):((value>>18)&0x3f)+1]
	}
	out := top + salt + output[0:22]
	if len(out) == 34 {
		return out, nil
	}
	return out, errors.New("produced is error password")
}

func hashMd5(value string) string {
	has := md5.New()
	has.Write([]byte(value))
	return string(has.Sum(nil))
}

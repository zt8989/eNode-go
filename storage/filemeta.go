package storage

import (
	"path/filepath"
	"strings"
)

func Ext(name string) string {
	if name == "" {
		return ""
	}
	ext := filepath.Ext(name)
	if ext == "" {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(ext, "."))
}

func GetFileType(name string) string {
	ext := Ext(name)
	if ext == "" {
		return ""
	}
	video := map[string]struct{}{
		"3gp": {}, "aaf": {}, "asf": {}, "avchd": {}, "avi": {}, "fla": {}, "flv": {},
		"m1v": {}, "m2v": {}, "m4v": {}, "mp4": {}, "mpg": {}, "mpe": {}, "mpeg": {},
		"mov": {}, "mkv": {}, "ogg": {}, "rm": {}, "svi": {},
	}
	audio := map[string]struct{}{
		"aiff": {}, "au": {}, "wav": {}, "flac": {}, "la": {}, "pac": {}, "m4a": {}, "ape": {},
		"rka": {}, "shn": {}, "tta": {}, "wv": {}, "wma": {}, "brstm": {}, "amr": {}, "mp2": {},
		"mp3": {}, "ogg": {}, "aac": {}, "mpc": {}, "ra": {}, "ots": {}, "vox": {}, "voc": {},
		"mid": {}, "mod": {}, "s3m": {}, "xm": {}, "it": {}, "asf": {},
	}
	image := map[string]struct{}{
		"cr2": {}, "pdn": {}, "pgm": {}, "pict": {}, "bmp": {}, "png": {}, "dib": {}, "djvu": {},
		"gif": {}, "psd": {}, "pdd": {}, "icns": {}, "ico": {}, "rle": {}, "tga": {}, "jpeg": {},
		"jpg": {}, "tiff": {}, "tif": {}, "jp2": {}, "jps": {}, "mng": {}, "xbm": {}, "xcf": {},
		"pcx": {},
	}
	pro := map[string]struct{}{
		"7z": {}, "ace": {}, "arc": {}, "arj": {}, "bzip2": {}, "cab": {}, "gzip": {}, "rar": {},
		"tar": {}, "zip": {}, "iso": {}, "nrg": {}, "img": {}, "adf": {}, "dmg": {}, "cue": {},
		"bin": {}, "cif": {}, "ccd": {}, "sub": {}, "raw": {},
	}
	if _, ok := video[ext]; ok {
		return "Video"
	}
	if _, ok := audio[ext]; ok {
		return "Audio"
	}
	if _, ok := image[ext]; ok {
		return "Image"
	}
	if _, ok := pro[ext]; ok {
		return "Pro"
	}
	return ""
}

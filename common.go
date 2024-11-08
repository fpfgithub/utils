package utils

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type WorldTime struct {
	Unixtime int64 `json:"unixtime"`
}

func GetContent(filePath string) string {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		// logger.Println("无法打开文件:", err)
		return ""
	}
	defer file.Close()

	// 读取文件内容
	content, err := io.ReadAll(file)
	if err != nil {
		// logger.Println("读取文件失败:", err)
		return ""
	}

	// 输出文件内容
	// logger.Println(string(content))
	return string(content)
}

// 写入文件
func WriteToFile(filePath string, content string) error {
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}

	return nil
}

func GenerateLogFile(fileName string) error {
	// 判断文件是否已经存在
	if _, err := os.Stat(fileName); err == nil {
		return nil
	}
	// 创建文件
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	// 设置文件权限为 777
	if err := f.Chmod(0777); err != nil {
		return err
	}
	return nil
}

func GenerateBatFile(wdPath, port, dirName string) error {
	// 生成文件名
	fileName := fmt.Sprintf("%s/startchrome%s.bat", wdPath, port)

	// 判断文件是否已经存在
	if _, err := os.Stat(fileName); err == nil {
		return nil
	}

	// 创建文件
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	// 创建带缓冲的写入器，并确保使用CRLF换行符
	writer := bufio.NewWriter(f)

	// 写入文件内容，确保换行符为CRLF
	content := fmt.Sprintf(
		"@echo off\r\n"+
			"echo;chrome start now......\r\n"+
			"start chrome.exe --remote-debugging-port=%s --user-data-dir=\"%s\"\r\n"+
			"echo;chrome start ok!\r\n"+
			"pause\r\n",
		port, dirName)

	_, err = writer.WriteString(content)
	if err != nil {
		return err
	}

	// 确保数据写入文件
	writer.Flush()

	return nil
}

// windows系统 执行bat命令
func RunCmdBat(wdPath, batName string) error {
	cmd := exec.Command("cmd.exe", "/C", "start ", "/B", fmt.Sprintf("%s\\%s.bat", wdPath, batName))
	// var out bytes.Buffer
	// cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		// logger.Println(err)
		return err
	}
	return nil
}

func IsInSlice(slice []string, target string) bool {
	for _, value := range slice {
		if value == target {
			return true
		}
	}
	return false
}

// 端口是否占用
func TcpGather(ip string, ports []string) map[string]string {
	// 检查 emqx 1883, 8083, 8080, 18083 端口
	results := make(map[string]string)
	// println(len(results))
	for _, port := range ports {
		address := net.JoinHostPort(ip, port)
		// 3 秒超时
		conn, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			results[port] = "failed"
			// todo log handler
		} else {
			if conn != nil {
				results[port] = "success"
				_ = conn.Close()
			} else {
				results[port] = "failed"
			}
		}
	}
	// println(len(results))
	// println(results["9222"])
	return results
}

func RunCmd(cmdStr string, isshell bool) error {
	var cmd *exec.Cmd
	if isshell {
		cmd = exec.Command("bash", "-c", cmdStr)
	} else {
		cmd = exec.Command(cmdStr)
	}
	// var out bytes.Buffer
	// var stderr bytes.Buffer
	// cmd.Stdout = &out
	// cmd.Stderr = &stderr
	err := cmd.Run()
	// fmt.Println(cmdStr)
	// fmt.Println(err)
	if err != nil {
		return err
	} else {
		return nil
	}
}

// 获取当前执行程序所在的绝对路径
func CurrentAbPathByExecutable() string {
	//sysType
	sysType := runtime.GOOS
	if sysType == "windows" {
		wdPath, _ := os.Getwd()
		return wdPath
	} else {
		exePath, _ := os.Executable()
		// if err != nil {
		// logger.Fatal(err)
		// }
		res, _ := filepath.EvalSymlinks(filepath.Dir(exePath))
		return res
	}
}

// 清空文件夹
func ClearDir(dir string) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			err := os.Remove(path)
			if err != nil {
				return err
			}
			// fmt.Println("Deleted file:", path)
		}
		return nil
	})
	if err != nil {
		// fmt.Println("Error:", err)
		return err
	}
	// fmt.Println("日志清理ok")
	return nil
}

func AutoExit() {
	fmt.Println("10秒钟后自动关闭...")
	time.Sleep(10 * time.Second)
	os.Exit(0)
}

// 创建目录
func CreateDirWithPermission(dirPath string, perm os.FileMode) error {
	// 判断目录是否存在
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		// 目录不存在，创建目录
		err := os.MkdirAll(dirPath, os.ModePerm)
		if err != nil {
			return err
		}
		fmt.Println("Directory created:", dirPath)
	}

	// 设置目录权限
	err := os.Chmod(dirPath, perm)
	if err != nil {
		return err
	}

	return nil
}

// 创建文件
func CreateFile(fileName string) {
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
	}
	// 关流(不关流会长时间占用内存)
	defer file.Close()
}

// 解密数据
func Decrypt(key, str string) (int64, error) {
	// 解码Base64字符串
	ciphertext, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return 0, err
	}

	// 创建解密器
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return 0, err
	}

	// 解密数据
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// 去掉填充字节
	unpadded, err := unpad(plaintext)
	if err != nil {
		return 0, err
	}

	// 解析时间戳
	var timestamp uint64
	for i := 0; i < 8; i++ {
		timestamp |= uint64(unpadded[i]) << (56 - 8*i)
	}

	// 返回时间戳
	return int64(timestamp), nil
}

// 去掉填充字节
func unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadByte := data[length-1]
	unpadLen := int(unpadByte)
	if unpadLen > length {
		return nil, fmt.Errorf("invalid padding length: %d", unpadLen)
	}
	return data[:length-unpadLen], nil
}

// 检查本地时间是否被修改
func CheckTimeDifference() error {
	// 获取本地时间的Unix时间戳
	localTimeUnix := time.Now().Unix()

	// 获取百度的时间
	resp, err := http.Get("https://www.baidu.com")
	if err != nil {
		return errors.New("检测到网络异常，请检查网络连接是否正常！")
	}
	defer resp.Body.Close()

	// 读取百度返回的响应头中的Date字段
	dateHeader := resp.Header.Get("Date")
	if dateHeader == "" {
		return errors.New("无法获取网络时间，请检查网络连接是否正常！")
	}

	// 解析Date字段
	networkTime, err := time.Parse(time.RFC1123, strings.TrimSpace(dateHeader))
	if err != nil {
		return errors.New("网络时间解析失败，请检查网络连接是否正常！")
	}

	// 检查两者的差值，主要防止本地时间被修改
	if networkTime.Unix()-localTimeUnix > 1800 {
		return errors.New("检测到异常网络，请检查网络连接是否正常！")
	}

	return nil
}

func getMacAddr() ([]string, error) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	macAddrMap := make(map[string]bool)
	var macAddrStrSlice []string
	for _, netInterface := range netInterfaces {
		macAddrStr := netInterface.HardwareAddr.String()
		if len(macAddrStr) == 0 {
			continue
		}
		if _, exist := macAddrMap[macAddrStr]; !exist {
			macAddrMap[macAddrStr] = true
			macAddrStrSlice = append(macAddrStrSlice, macAddrStr)
		}
	}
	return macAddrStrSlice, nil
}

func getOSVersion() (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// 对于windows，你也许可以调用一些类似 `wmic os get caption` 的命令来获取版本信息
		cmd = exec.Command("wmic", "os", "get", "caption")
	} else {
		// 我们假设其他所有系统都支持 `uname -a` 命令，实际可能需要更复杂的逻辑来处理不同的Unix系统
		cmd = exec.Command("uname", "-a")
	}
	// 执行命令，并获取输出
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	// 返回去除尾部空格的结果
	return strings.TrimSpace(string(out)), nil
}

func GenerateDeviceID() (string, error) {
	macAddrSlice, err := getMacAddr()
	if err != nil {
		macAddrSlice = nil
	}
	osVersion, err := getOSVersion()
	if err != nil {
		osVersion = ""
	}
	deviceInfo := runtime.GOOS +
		runtime.GOARCH +
		strconv.Itoa(runtime.NumCPU())
	if len(macAddrSlice) > 0 {
		deviceInfo = strings.Join(macAddrSlice, "") + deviceInfo
	}
	if len(osVersion) > 0 {
		deviceInfo += osVersion
	}
	hasher := md5.New()
	hasher.Write([]byte(deviceInfo))
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

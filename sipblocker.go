package main

import (
	"os"
	"fmt"
	"log"
	"net"
	"bufio"
	"bytes"
	"regexp"
	"strings"
	"strconv"
	"os/exec"
	"net/smtp"
	"crypto/md5"
	"crypto/aes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"crypto/cipher"
	_"github.com/lib/pq"
	"github.com/takama/daemon"
	"github.com/yosh0/mtproto"
)

const (
  	_DN  		= "sipblocker"
  	_DD  		= "Phreakers blocker"
	_LT		= "\x0D\x0A"
	_KVT 		= ":"               // header value separator
	_READ_BUF     	= 512               // buffer size for socket reader
	_CMD_END      	= "--END COMMAND--" // Asterisk command data end
	_CACL 		= "Device does not match ACL" // cause acl
	_CPASS 		= "Wrong password" // cause wrong pass
	_CCRF		= "Challenge Response Failed" //cause challenge response failed
)

var (
	_PT_BYTES = []byte(_LT + _LT) // packet separator
  	errlog *log.Logger
	AMIhost, AMIuser, AMIpass, AMIport string
	DBPass, DBName, DBHost, DBPort, DBUser, DBSSL string
	LOGPATH = ""
	TG []string
	TGPATH string
	BANCHAIN, BANTABLE, BANCMD, BANEVENT string
	BANQUERYD, BANQUERYDW, BANQUERYI string
	CALLCHAIN, CALLTABLE, CALLQUERYS string
	MAILSERVER, MAILPORT, MAILDOMAIN, MAILHEADER, MAILTO, MAIL string
	LENGTHOUTERNUM, LENGTHINNERNUM int
	PORTNUM string

	unquotedChar  = `[^",\\{}\s(NULL)]`
    	unquotedValue = fmt.Sprintf("(%s)+", unquotedChar)
    	quotedChar  =	`[^"\\]|\\"|\\\\`
    	quotedValue =	fmt.Sprintf("\"(%s)*\"", quotedChar)
	arrayValue =	fmt.Sprintf("(?P<value>(%s|%s))", unquotedValue, quotedValue)
	arrayExp =	regexp.MustCompile(fmt.Sprintf("((%s)(,)?)", arrayValue))
)

type Config struct {
	Pg Pg
	Tg Tg
	Ban Ban
	Mail Mail
	LogDir LogDir
	Numbers Numbers
	SIPBlockerAmi SIPBlockerAmi
}

type Numbers struct {
	Lengtinnernum 	int
	Lengtouternum 	int
	PortNum		string
}

type LogDir struct {
	Path string
}

type Ban struct {
	BanChain string
	BanTable string
	BanQueryD string
	BanQueryDW string
	BanQueryI string
	CallChain string
	CallTable string
	CallQueryS string
	Command string
	Event string
}

type Tg struct {
	Rcp []string
	Path string
}

type SIPBlockerAmi struct {
	RemotePort string
	RemoteHost string
	Username   string
	Password   string
}

type Pg struct {
	DBPort string
	DBHost string
	DBUser string
	DBPass string
	DBName string
	DBSSL string
}

type Mail struct {
	Server	string
	Port	string
	Domain	string
	Mailto	string
	Mail	string
	Header	string
}

type CallcenterLog struct {
	Path  string
}

type Message map[string]string

type Service struct {
	daemon.Daemon
}

func (service *Service) Manage() (string, error) {
	usage := "Usage: myservice install | remove | start | stop | status\n"
	if len(os.Args) > 1 {
		command := os.Args[1]
		switch command {
		case "install":
			return service.Install()
		case "remove":
	    		return service.Remove()
		case "start":
	    		return service.Start()
		case "stop":
	    		return service.Stop()
		case "status":
	    		return service.Status()
		default:
	    		return usage, nil
		}
    	}
	eventGet()
    	return usage, nil
}

func eventGet() {
	conn, err := net.Dial("tcp", AMIhost+":"+AMIport)
	if err != nil {
		LoggerString("Connection to host "+AMIhost+" error")
		NotifyTG("Connection to host "+AMIhost+" error")
		os.Exit(0)
	}
	fmt.Fprintf(conn, "Action: Login"+_LT)
	fmt.Fprintf(conn, "Username: "+AMIuser+_LT)
	fmt.Fprintf(conn, "Secret: "+AMIpass+_LT+_LT)
	r := bufio.NewReader(conn)
	pbuf := bytes.NewBufferString("")
	buf := make([]byte, _READ_BUF)
	for {
		rc, err := r.Read(buf)
		if err != nil {
			LoggerString("Read from socket error")
			break
		}
		wb, err := pbuf.Write(buf[:rc])
		if err != nil || wb != rc { // can't write to data buffer, just skip
			continue
		}
		for pos := bytes.Index(pbuf.Bytes(), _PT_BYTES); pos != -1; pos = bytes.Index(pbuf.Bytes(), _PT_BYTES) {
			bp := make([]byte, pos + len(_PT_BYTES))
			r, err := pbuf.Read(bp)                    // reading packet to separate puffer
			if err != nil || r != pos + len(_PT_BYTES) { // reading problems, just skip
				continue
			}
			m := make(Message)
			for _, line := range bytes.Split(bp, []byte(_LT)) {
				if len(line) == 0 {
					continue
				}
				kvl := bytes.Split(line, []byte(_KVT+" "))
				if len(kvl) == 1 {
					if string(line) != _CMD_END {
						m["CmdData"] += string(line)
					}
					continue
				}
				k := bytes.TrimSpace(kvl[0])
				v := bytes.TrimSpace(kvl[1])
				m[string(k)] = string(v)
			}
			eventHandler(m)
		}
	}
}

func eventHandler(E map[string]string) {
	switch E["Event"] {
	case "FailedACL" :
		FailedACL(E)
	case "InvalidAccountID" :
		InvalidAccountID(E)
	case "UnexpectedAddress" :
		UnexpectedAddress(E)
	case "InvalidPassword" :
		InvalidPassword(E)
	case "ChallengeResponseFailed" :
		ChallengeResponseFailed(E)
	case "RequestBadFormat" :
		RequestBadFormat(E)
	case "UserEvent" :
		UserEvent(E)
	case "PeerStatus" :
		PeerStatus(E)
	default :

	}
}

func PeerStatus(e map[string]string) {
	LoggerMap(e)
	num := strings.Split(e["Peer"], "/")
	LoggerString("Num1 " + num[1])
	if len(num[1]) == LENGTHINNERNUM && e["PeerStatus"] == "Registered" {
		LoggerString("Num2 " + num[1] + " PeerStatus " + e["PeerStatus"])
		rex, err := regexp.Compile(`^(\S*)\:(\S*)$`)
		res := rex.FindStringSubmatch(e["Address"])
		if res != nil {
			LoggerMap(e)
			port := res[2]
			if port != PORTNUM {
				msg := fmt.Sprintf("%s %sNumber: %s %sAddress: %s", e["Event"], _LT, e["Peer"], _LT, e["Address"])
				NotifyMail(e["WrongPort"], e["Peer"], msg, MAILTO)
			}
		}
		if err != nil {
			LoggerString(err.Error())
		}
	}
}

func UserEvent(e map[string]string) {
	switch e["UserEvent"] {
	case BANEVENT :
		Blocker(e)
	default :

	}
}

func RAddrGet(a string) (string) {
	raddr := strings.Split(a, "/")
	return raddr[2]
}

func FailedACL(e map[string]string) {
	LoggerMap(e)
	raddr := RAddrGet(e["RemoteAddress"])
	msg := fmt.Sprintf("%s %sNumber: %s %sIP Address: %s %sACL Name: %s %sProto: %s",
		e["Event"], _LT, e["AccountID"], _LT, raddr, _LT, e["ACLName"], _LT, e["Service"])
	BlockerBan(raddr, e["AccountID"], _CACL)
	NotifyMail(e["Event"], e["AccountID"], msg, MAILTO)
}

func InvalidAccountID(e map[string]string) {
	LoggerMap(e)
	raddr := RAddrGet(e["RemoteAddress"])
	msg := fmt.Sprintf("%s %sNumber: %s %sIP Address: %s",
		e["Event"], _LT, e["AccountID"], _LT, raddr)
	NotifyTG(msg)
	NotifyMail(e["Event"], e["AccountID"], msg, MAILTO)
}

func UnexpectedAddress(e map[string]string) {
	LoggerMap(e)
	raddr := RAddrGet(e["RemoteAddress"])
	msg := fmt.Sprintf("%s %sNumber: %s %sIP Address: %s",
		e["Event"], _LT, e["AccountID"], _LT, raddr)
	NotifyTG(msg)
	NotifyMail(e["Event"], e["AccountID"], msg, MAILTO)
}

func InvalidPassword(e map[string]string) {
	LoggerMap(e)
	raddr := RAddrGet(e["RemoteAddress"])
	msg := fmt.Sprintf("%s %sNumber: %s %sIP Address: %s",
		e["Event"], _LT, e["AccountID"], _LT, raddr)
	BlockerBan(raddr, e["AccountID"], _CPASS)
	NotifyTG(msg)
	NotifyMail(e["Event"], e["AccountID"], msg, MAILTO)

}

func ChallengeResponseFailed(e map[string]string) {
	LoggerMap(e)
	raddr := RAddrGet(e["RemoteAddress"])
	msg := fmt.Sprintf("%s %s Number1: %s %s Number2: %s %s IP Address: %s",
		e["Event"], _LT, e["AccountID"], _LT, e["ExpectedResponse"], _LT, raddr)
	NotifyTG(msg)
	BlockerBan(raddr, e["AccountID"], _CCRF)
	NotifyMail(e["Event"], e["AccountID"], msg, MAILTO)
}

func RequestBadFormat(e map[string]string) {

}

func BlockerCheckIP(i string) bool {
	cmd := fmt.Sprintf("%s -nL %s | grep %s | wc -l", BANCMD, BANCHAIN, i)
	blk, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		LoggerErr(err)
	} else {
		tblk := strings.Trim(string(blk), "\n")
		if tblk > "0" {
			LoggerByte(blk)
			return true
		}
	}
	return false
}

func Blocker(e map[string]string) {
	LoggerMap(e)
	if e["Act"] == "Unban" && len(e["Ip"]) != 0 {
		BlockerUnban(e["Ip"])
	}
}

func BlockerUnban(i string) {
	blk, err := exec.Command(BANCMD, "-D", BANCHAIN, "-s", i, "-j", "DROP").Output()
	if err != nil {
		LoggerErr(err)
	} else {
		LoggerByte(blk)
	}
	query := fmt.Sprintf(BANQUERYDW, BANTABLE, i)
	sqlPut(query)
	LoggerString(query)
}

func BlockerBan(raddr string, accountid string, cause string) {
	if BlockerCheckIP(raddr) == false {
		blk, err := exec.Command(BANCMD, "-I", BANCHAIN, "1", "-s", raddr, "-j", "DROP").Output()
		if err != nil {
			LoggerErr(err)
		} else {
			LoggerByte(blk)
		}
		query := fmt.Sprintf(BANQUERYI, BANTABLE, raddr, accountid, cause)
		sqlPut(query)
	}
}

func BlockerInit() {
	BlockerDel()
	BlockerAdd()
	BlockerRestore()
}

func BlockerAdd() {
	blk, err := exec.Command(BANCMD, "-N", BANCHAIN).Output()
	blk, err = exec.Command(BANCMD, "-A", BANCHAIN, "-j", "RETURN").Output()
	blk, err = exec.Command(BANCMD, "-I", "INPUT", "-j", BANCHAIN).Output()

	blk, err = exec.Command(BANCMD, "-N", CALLCHAIN).Output()
	blk, err = exec.Command(BANCMD, "-A", CALLCHAIN, "-j", "RETURN").Output()
	blk, err = exec.Command(BANCMD, "-I", "INPUT", "-j", CALLCHAIN).Output()
	if err != nil {
		LoggerErr(err)
	} else {
		LoggerByte(blk)
	}
}

func BlockerDel() {
	blk, err := exec.Command(BANCMD, "-D", "INPUT", "-j", BANCHAIN).Output()
	blk, err = exec.Command(BANCMD, "-F", BANCHAIN).Output()
	blk, err = exec.Command(BANCMD, "-X", BANCHAIN).Output()

	blk, err = exec.Command(BANCMD, "-D", "INPUT", "-j", CALLCHAIN).Output()
	blk, err = exec.Command(BANCMD, "-F", CALLCHAIN).Output()
	blk, err = exec.Command(BANCMD, "-X", CALLCHAIN).Output()
	if err != nil {
		LoggerErr(err)
	} else {
		LoggerByte(blk)
	}
	query := fmt.Sprintf(BANQUERYD, BANTABLE)
	sqlPut(query)
	LoggerString(query)
}

func BlockerRestore() {
	query := fmt.Sprintf(CALLQUERYS, CALLTABLE)
	blist := sqlGetArray(query)
	if len(blist) != 0 {
		for _, i := range blist {
			rex, err := regexp.Compile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
			res := rex.FindStringSubmatch(i)
			if res != nil {
				_, err = exec.Command(BANCMD, "-I", CALLCHAIN, "1", "-s", i, "-j", "DROP").Output()
			}
			if err != nil {
				LoggerErr(err)
			}
		}
	} else {
		NotifyTG(_DN+" sipblocker list = 0")
	}
	blist = make([]string, 0)
}

func NotifyMail(action string, category string, message string, mailto string) {
	hname, err := os.Hostname()
	subj_hname := fmt.Sprintf("[%s]", strings.ToUpper(hname))
	subj_category := fmt.Sprintf("[%s]", strings.ToUpper(category))
	subj_action := fmt.Sprintf("[%s]", action)
	c, err := smtp.Dial(fmt.Sprintf("%s:%s", MAILSERVER, MAILPORT))
	if err != nil {
		LoggerString("Error: Cant connect to Mail server")
		LoggerErr(err)
	} else {
		c.Mail(fmt.Sprintf("%s@%s", hname, MAILDOMAIN))
		c.Rcpt(fmt.Sprintf("%s@%s", mailto, MAILDOMAIN))
		wc, err := c.Data()
		if err != nil {
			LoggerErr(err)
		}
		msg := []byte(fmt.Sprintf(MAILHEADER,
			_LT, mailto, MAILDOMAIN, _LT, subj_hname, subj_action, subj_category, _LT, _LT, message, _LT))
		_, err = wc.Write(msg)
		defer wc.Close()
		LoggerString(string(msg))
		if err != nil {
			LoggerErr(err)
		}
		err = wc.Close()
		if err != nil {
			LoggerErr(err)
		}
		c.Quit()
	}
	defer c.Close()
}

func NotifyTG(tg_msg string) {
	LoggerString(tg_msg)
	m, err := mtproto.NewMTProto(TGPATH)
	if err != nil {
		LoggerString("Create failed")
		LoggerErr(err)
	}
	err = m.Connect()
	if err != nil {
		LoggerString("Connect failed")
		LoggerErr(err)
	}
	for rcps, each := range TG {
		rcp := string(rcps)
		e := string(each)
		id, err := strconv.ParseInt(each, 10, 32)
		LoggerString("Send TG_MSG to " + e + " " + rcp)
		err = m.SendMsg(int32(id), tg_msg)
		if (err != nil) {
			LoggerErr(err)
		}
	}
}

func sqlPut(query string) {
	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		DBHost, DBPort, DBUser, DBPass, DBName, DBSSL)
	db, err := sql.Open("postgres", dbinfo)
	err = db.Ping()
	if (err != nil) {
		LoggerString(err.Error())
		NotifyTG(err.Error())
		os.Exit(0)
	}
	result, err := db.Exec(query)
	if err != nil {
		LoggerErr(err)
	}
	result.LastInsertId()
	db.Close()
}

func sqlGetArray(query string) []string {
	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		DBHost, DBPort, DBUser, DBPass, DBName, DBSSL)
	db, err := sql.Open("postgres", dbinfo)
	rows, err := db.Query(query)
	if (err != nil) {
		LoggerErr(err)
	} else {

	}
	defer rows.Close()
	var arr string
	var el []string
	for rows.Next() {
		rows.Scan(&arr)
		VAR := pgArrayToSlice(arr) //var for single field query output
		el = append(el, VAR...)
	}
	if (len(el) < 1) {
		el = append(el, "Err")
	}
	db.Close()
	return el
}

func pgArrayToSlice(array string) []string {
    var valueIndex int
    results := make([]string, 0)
    matches := arrayExp.FindAllStringSubmatch(array, -1)
    for _, match := range matches {
        s := match[valueIndex]
        s = strings.Trim(s, "\"")
        results = append(results, s)
    }
    return results
}

func decrypt(cipherstring string, keystring string) []byte {
	ciphertext := []byte(cipherstring)
	key := []byte(keystring)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("Text is too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext
}

func init() {
	k := os.Getenv("ASTCONFIG")
	f, err := os.Open(os.Getenv("ASTCONF"))

	if err != nil {
		LoggerString(err.Error())
	}
	data := make([]byte, 10000)
	count, err := f.Read(data)
	if err != nil {
		log.Fatal(err)
	}

	hasher := md5.New()
    	hasher.Write([]byte(k))
    	key := hex.EncodeToString(hasher.Sum(nil))

	content := string(data[:count])
	df := decrypt(content, key)
	c := bytes.NewReader(df)
	decoder := json.NewDecoder(c)
	conf := Config{}
	err = decoder.Decode(&conf)
	if err != nil {
		LoggerString(err.Error())
	}

	AMIport = conf.SIPBlockerAmi.RemotePort
	AMIhost = conf.SIPBlockerAmi.RemoteHost
	AMIuser = conf.SIPBlockerAmi.Username
	AMIpass = conf.SIPBlockerAmi.Password

	LOGPATH = conf.LogDir.Path

	BANCHAIN = conf.Ban.BanChain
	BANTABLE = conf.Ban.BanTable
	BANQUERYD = conf.Ban.BanQueryD
	BANQUERYDW = conf.Ban.BanQueryDW
	BANQUERYI = conf.Ban.BanQueryI

	CALLCHAIN = conf.Ban.CallChain
	CALLTABLE = conf.Ban.CallTable
	CALLQUERYS = conf.Ban.CallQueryS
	BANEVENT = conf.Ban.Event
	BANCMD = conf.Ban.Command

	MAILSERVER = conf.Mail.Server
	MAILPORT = conf.Mail.Port
	MAILDOMAIN = conf.Mail.Domain
	MAILHEADER = conf.Mail.Header
	MAILTO = conf.Mail.Mailto
	MAIL = conf.Mail.Mail

	DBPass = conf.Pg.DBPass
	DBName = conf.Pg.DBName
	DBHost = conf.Pg.DBHost
	DBPort = conf.Pg.DBPort
	DBUser = conf.Pg.DBUser
	DBSSL = conf.Pg.DBSSL

	LENGTHINNERNUM = conf.Numbers.Lengtinnernum
	LENGTHOUTERNUM = conf.Numbers.Lengtouternum
	PORTNUM = conf.Numbers.PortNum

	TG = conf.Tg.Rcp
	TGPATH = conf.Tg.Path
	BlockerInit()
	NotifyTG("Start/Restart " + _DN + " " + _DD)
}

func main() {
	srv, err := daemon.New(_DN, _DD)
    	if err != nil {
		errlog.Println("Error 1: ", err)
		os.Exit(1)
    	}
    	service := &Service{srv}
    	status, err := service.Manage()
    	if err != nil {
		errlog.Println(status, "\nError 2: ", err)
		os.Exit(1)
    	}
    	fmt.Println(status)
}

func LoggerString(s string) {
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(s)
}

func LoggerMap(m map[string]string) {
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
 	log.SetOutput(f)
  	log.Print(m)
}

func LoggerErr(s error) {
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(s)
}

func LoggerByte(s []byte) {
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(s)
}

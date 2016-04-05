package main

import (
	"os"
	"fmt"
	"log"
	"net"
	"bufio"
	"bytes"
	"strings"
	"strconv"
	"os/exec"
	"database/sql"
	"encoding/json"
	_"github.com/lib/pq"
	"github.com/takama/daemon"
	"github.com/sdidyk/mtproto"
	"github.com/yosh0/simpleMailNotify"

)

const (
  	_DN  		= "sipblocker"
  	_DD  		= "Phreakers blocker"
	_LT		= "\r\n"            // packet line separator
	_KVT 		= ":"               // header value separator
	_READ_BUF     	= 512               // buffer size for socket reader
	_CMD_END      	= "--END COMMAND--" // Asterisk command data end
	_CACL 		= "Device does not match ACL" // cause acl
	_CPASS 		= "Wrong password" // cause wrong pass
)

var (
	M = make(map[string][]map[string]string) //MAIL MAP
	DBI =  make(map[string][]map[string]string) //DB CONNECT MAP
	_PT_BYTES = []byte(_LT + _LT) // packet separator
  	errlog *log.Logger
	AMIhost, AMIuser, AMIpass, AMIport string
	DBPass, DBName, DBHost, DBPort, DBUser, DBSSL string
	LOGPATH = ""
	TG []string
	TGPATH string
	BANCHAIN, BANTABLE, BANCOMMAND string
)


type Config struct {
	Pg Pg
	Tg Tg
	Ban Ban
	Mail Mail
	LogDir LogDir
	SIPBlockerAmi SIPBlockerAmi
}

type LogDir struct {
	Path string
}

type Ban struct {
	Chain string
	Table string
	Command string
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
}

type CallcenterLog struct {
	Path  string
}

type Message map[string]string

type Service struct {
	daemon.Daemon
}

func (service *Service) Manage() (string, error) {
	usage := "Usage: myservice install | remove | start | stop | status\nconfig 'asterisk_config.json' should be placed in /etc/asterisk"
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
	if (E["Event"] == "FailedACL") {
		FailedACL(E)
	} else if (E["Event"] == "InvalidAccountID") {
		InvalidAccountID(E)
	} else if (E["Event"] == "UnexpectedAddress") {
		UnexpectedAddress(E)
	} else if (E["Event"] == "InvalidPassword") {
		InvalidPassword(E)
	} else if (E["Event"] == "ChallengeResponseFailed") {
		ChallengeResponseFailed(E)
	} else if (E["Event"] == "RequestBadFormat") {
		RequestBadFormat(E)
	}
}

func RAddrGet(a string) (string) {
	raddr := strings.Split(a, "/")
	LoggerString("REMOTE ADDR " + raddr[2])
	return raddr[2]
}

func FailedACL(e map[string]string) {
	LoggerMap(e)
	raddr := RAddrGet(e["RemoteAddress"])
	msg := fmt.Sprintf("%s %s Number %s %s IP Address %s %s ACL Name %s %s Proto %s",
		e["Event"], _LT, e["AccountID"], _LT, raddr, _LT, e["ACLName"], _LT, e["Service"])
	blk, err := exec.Command(BANCOMMAND, "-I", BANCHAIN, "1", "-s", raddr, "-j", "DROP").Output()
	if err != nil {
		LoggerErr(err)
	} else {
		LoggerByte(blk)
	}
	query := fmt.Sprintf("INSERT INTO %s (ip, num, cause) VALUES ('%s', '%s', '%s')",
		BANTABLE, raddr, e["AccountID"], _CACL)
	sqlPut(query)
	simpleMailNotify.Notify(e["Event"], msg, M)
}

func InvalidAccountID(e map[string]string) {
	LoggerMap(e)
	simpleMailNotify.Notify(e["Event"], "Text", M)
}

func UnexpectedAddress(e map[string]string) {
	LoggerMap(e)
	simpleMailNotify.Notify(e["Event"], "Text", M)
}

func InvalidPassword(e map[string]string) {
	LoggerMap(e)
	raddr := RAddrGet(e["RemoteAddress"])
	msg := fmt.Sprintf("%s %s Number %s %s IP Address %s",
		e["Event"], _LT, e["AccountID"], _LT, raddr)
	blk, err := exec.Command(BANCOMMAND, "-I", BANCHAIN, "1", "-s", raddr, "-j", "DROP").Output()
	if err != nil {
		LoggerErr(err)
	} else {
		LoggerByte(blk)
	}
	query := fmt.Sprintf("INSERT INTO %s (ip, num, cause) VALUES ('%s', '%s', '%s')",
		BANTABLE, raddr, e["AccountID"], _CPASS)
	sqlPut(query)
	simpleMailNotify.Notify(e["Event"], msg, M)
}

func ChallengeResponseFailed(e map[string]string) {
	LoggerMap(e)
	simpleMailNotify.Notify(e["Event"], "Text", M)
}

func RequestBadFormat(e map[string]string) {
	LoggerMap(e)
//	raddr := RAddrGet(e["RemoteAddress"])
//	msg := e["Event"] + _LT + e["AccountID"] + _LT + e["RequestType"] + _LT + e["Severity"] +  _LT + raddr
//	simpleMailNotify.Notify(e["Event"], msg, M)
}

func init() {
	file, e1 := os.Open("/etc/asterisk/asterisk_config.json")
	if e1 != nil {
		fmt.Println("Error: ", e1)
		os.Exit(88)
	}
	decoder := json.NewDecoder(file)
	conf := Config{}
	err := decoder.Decode(&conf)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(88)
	}
	AMIport = conf.SIPBlockerAmi.RemotePort
	AMIhost = conf.SIPBlockerAmi.RemoteHost
	AMIuser = conf.SIPBlockerAmi.Username
	AMIpass = conf.SIPBlockerAmi.Password

	LOGPATH = conf.LogDir.Path

	BANCHAIN = conf.Ban.Chain
	BANTABLE = conf.Ban.Table
	BANCOMMAND = conf.Ban.Command

	var m = make(map[string]string)
	m["Server"] = conf.Mail.Server
	m["Port"] = conf.Mail.Port
	m["Domain"] = conf.Mail.Domain
	m["Mailto"] = conf.Mail.Mailto
	M["M"] = append(M["M"], m)

	DBPass = conf.Pg.DBPass
	DBName = conf.Pg.DBName
	DBHost = conf.Pg.DBHost
	DBPort = conf.Pg.DBPort
	DBUser = conf.Pg.DBUser
	DBSSL = conf.Pg.DBSSL

	var d = make(map[string]string)
	d["dbPass"] = conf.Pg.DBPass
	d["dbName"] = conf.Pg.DBName
	d["dbHost"] = conf.Pg.DBHost
	d["dbPort"] = conf.Pg.DBPort
	d["dbUser"] = conf.Pg.DBUser
	DBI["PG"] = append(DBI["PG"], d)

	TG = conf.Tg.Rcp
	TGPATH = conf.Tg.Path
	NotifyTG("Start/Restart " + _DN + " " + _DD)
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
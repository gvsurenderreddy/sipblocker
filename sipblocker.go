package main

import (
	"github.com/yosh0/simpleMailNotify"
	"github.com/takama/daemon"
	"os"
	"fmt"
	"encoding/json"
	"log"
	"net"
	"bufio"
	"bytes"
	"flag"
	"strings"
	"os/exec"
	"database/sql"
	_ "github.com/lib/pq"
)

const (
  	_DAEMON_NAME  = "sipblocker"
  	_DAEMON_DESC  = "Phreakers blocker"
	_LT		= "\r\n"            // packet line separator
	_KEY_VAL_TERM = ":"               // header value separator
	_READ_BUF     = 512               // buffer size for socket reader
	_CMD_END      = "--END COMMAND--" // Asterisk command data end
)

var (
	M = make(map[string][]map[string]string) //MAIL MAP
	DBI =  make(map[string][]map[string]string) //DB CONNECT MAP
	_PT_BYTES = []byte(_LT + _LT) // packet separator
  	errlog *log.Logger
	AMIhost, AMIuser, AMIpassword, AMIport string
	LOGPATH = ""
)


type Config struct {
	SIPBlockerAmi SIPBlockerAmi
	Mail Mail
	CallcenterLog CallcenterLog
	Pg Pg
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
	conn, _ := net.Dial("tcp", AMIhost + ":" + AMIport)
	fmt.Fprintf(conn, "Action: Login\r\n")
	fmt.Fprintf(conn, "Username:" + AMIuser + "\r\n")
	fmt.Fprintf(conn, "Secret:" + AMIpassword + "\r\n\r\n")
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
				kvl := bytes.Split(line, []byte(_KEY_VAL_TERM))
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

//iptables and BD test
func FailedACL(e map[string]string) {
	LoggerMap(e)
	raddr := RAddrGet(e["RemoteAddress"])
	msg := e["Event"] + _LT + "Number " + e["AccountID"] + _LT + "IP Address " + raddr + _LT + "ACL Name " + e["ACLName"] + _LT + "Proto " + e["Service"]
	blk, err := exec.Command("iptables", "-I", "fail2ban-asterisk", "1", "-s", raddr, "-j", "DROP").Output() //test
	if err != nil {
		LoggerErr(err)
	} else {
		LoggerByte(blk)
	}
	sqlPut("INSERT INTO fail2ban_temp (ip, num, cause) VALUES ('" + raddr + "', '" + e["AccountID"] + "', 'Device does not match ACL')")
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

//iptables and BD test
func InvalidPassword(e map[string]string) {
	LoggerMap(e)
	raddr := RAddrGet(e["RemoteAddress"])
	msg := e["Event"] + _LT + "Number " + e["AccountID"] + _LT + "IP Address " + raddr
	blk, err := exec.Command("iptables", "-I", "fail2ban-asterisk", "1", "-s", raddr, "-j", "DROP").Output() //test
	if err != nil {
		LoggerErr(err)
	} else {
		LoggerByte(blk)
	}
	sqlPut("INSERT INTO fail2ban_temp (ip, num, cause) VALUES ('" + raddr + "', '" + e["AccountID"] + "', 'Wrong password')")
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
	flag.StringVar(&AMIport, "port", conf.SIPBlockerAmi.RemotePort, "AMI port")
	flag.StringVar(&AMIhost, "host", conf.SIPBlockerAmi.RemoteHost, "AMI host")
	flag.StringVar(&AMIuser, "user", conf.SIPBlockerAmi.Username, "AMI user")
	flag.StringVar(&AMIpassword, "password", conf.SIPBlockerAmi.Password, "AMI secret")
	flag.Parse()
	LOGPATH = conf.CallcenterLog.Path

	var m = make(map[string]string)
	m["Server"] = conf.Mail.Server
	m["Port"] = conf.Mail.Port
	m["Domain"] = conf.Mail.Domain
	m["Mailto"] = conf.Mail.Mailto
	M["M"] = append(M["M"], m)

	var d = make(map[string]string)
	d["dbPass"] = conf.Pg.DBPass
	d["dbName"] = conf.Pg.DBName
	d["dbHost"] = conf.Pg.DBHost
	d["dbPort"] = conf.Pg.DBPort
	d["dbUser"] = conf.Pg.DBUser
	DBI["PG"] = append(DBI["PG"], d)
}

func sqlPut(query string) {
	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		DBI["PG"][0]["dbHost"],
		DBI["PG"][0]["dbPort"],
		DBI["PG"][0]["dbUser"],
		DBI["PG"][0]["dbPass"],
		DBI["PG"][0]["dbName"])
	db, err := sql.Open("postgres", dbinfo)
	if (err != nil) {
		fmt.Println(err)
	}
	result, err := db.Exec(query)
	if err != nil {
		LoggerErr(err)
	}
	result.LastInsertId()
	db.Close()
}

func main() {
	srv, err := daemon.New(_DAEMON_NAME, _DAEMON_DESC)
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
	f, _ := os.OpenFile(LOGPATH, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(s)
}

func LoggerMap(m map[string]string) {
	f, _ := os.OpenFile(LOGPATH, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
 	log.SetOutput(f)
  	log.Print(m)
}

func LoggerErr(s error) {
	f, _ := os.OpenFile(LOGPATH, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(s)
}

func LoggerByte(s []byte) {
	f, _ := os.OpenFile(LOGPATH, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(s)
}